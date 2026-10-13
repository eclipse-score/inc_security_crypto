/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_CRYPTO_SRC_DAEMON_CONTROL_PLANE_CANCELLATION_TOKEN_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CONTROL_PLANE_CANCELLATION_TOKEN_HPP

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace score::crypto::daemon::control_plane
{

namespace detail
{

struct CancellationCallback final
{
    explicit CancellationCallback(std::function<void()> callback_arg) : callback(std::move(callback_arg)) {}

    bool IsActive() noexcept
    {
        std::lock_guard<std::mutex> lock(mutex);
        return active;
    }

    void Invoke() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!active)
            {
                return;
            }
            ++in_flight;
            invoking_thread = std::this_thread::get_id();
        }

        callback();

        std::function<void()> callback_to_destroy;
        {
            std::lock_guard<std::mutex> lock(mutex);
            --in_flight;
            if (in_flight == 0U)
            {
                invoking_thread = std::thread::id{};
                if (!active)
                {
                    callback_to_destroy = std::move(callback);
                }
            }
        }
        condition.notify_all();
    }

    void DeactivateAndWait() noexcept
    {
        std::function<void()> callback_to_destroy;
        {
            std::unique_lock<std::mutex> lock(mutex);
            active = false;
            if ((in_flight > 0U) && (invoking_thread == std::this_thread::get_id()))
            {
                return;
            }
            condition.wait(lock, [this] {
                return in_flight == 0U;
            });
            callback_to_destroy = std::move(callback);
        }
    }

    std::function<void()> callback;
    std::mutex mutex{};
    std::condition_variable condition{};
    bool active{true};
    std::size_t in_flight{0U};
    std::thread::id invoking_thread{};
};

struct CancellationState final
{
    std::atomic_bool requested{false};
    std::mutex mutex;
    std::vector<std::shared_ptr<CancellationCallback>> callbacks;
};

}  // namespace detail

/// RAII handle for a callback registered with a cancellation token.
///
/// Destroying or replacing the registration deactivates the callback.
class CancellationRegistration final
{
  public:
    CancellationRegistration() noexcept = default;

    ~CancellationRegistration() noexcept
    {
        DeregisterAndWait();
    }

    CancellationRegistration(const CancellationRegistration&) = delete;
    CancellationRegistration& operator=(const CancellationRegistration&) = delete;

    CancellationRegistration(CancellationRegistration&& other) noexcept : callback_(std::move(other.callback_)) {}

    CancellationRegistration& operator=(CancellationRegistration&& other) noexcept
    {
        if (this != &other)
        {
            DeregisterAndWait();
            callback_ = std::move(other.callback_);
        }
        return *this;
    }

    /// Deactivates this callback and waits for an invocation on another thread to finish.
    /// When called from the callback itself, it deactivates without waiting for its own return.
    void DeregisterAndWait() noexcept
    {
        if (callback_ != nullptr)
        {
            auto callback = std::move(callback_);
            callback->DeactivateAndWait();
        }
    }

  private:
    explicit CancellationRegistration(std::shared_ptr<detail::CancellationCallback> callback) noexcept
        : callback_(std::move(callback))
    {
    }

    std::shared_ptr<detail::CancellationCallback> callback_;

    friend class CancellationToken;
};

/// Read-only handle used to observe and react to a shared cancellation state.
///
/// A default-constructed token is not associated with a source and never reports
/// cancellation.
class CancellationToken final
{
  public:
    CancellationToken() = default;

    /// Returns whether cancellation has been requested for this token.
    bool IsCancellationRequested() const noexcept
    {
        return state_ != nullptr && state_->requested.load(std::memory_order_acquire);
    }

    /// Registers a non-throwing callback to be invoked when cancellation is requested.
    ///
    /// If cancellation was already requested, the callback is invoked before
    /// this function returns and an empty registration is returned.
    ///
    /// @tparam Callback Callable type with a non-throwing call operator.
    /// @param callback Function to invoke on cancellation.
    /// @return Registration that keeps the callback active, or an empty
    ///         registration for an unassociated token or empty callback.
    template <typename Callback, typename = typename std::enable_if<noexcept(std::declval<Callback&>()())>::type>
    CancellationRegistration RegisterCallback(Callback&& callback) const
    {
        std::function<void()> callback_function{std::forward<Callback>(callback)};
        if ((state_ == nullptr) || !callback_function)
        {
            return {};
        }

        auto callback_state = std::make_shared<detail::CancellationCallback>(std::move(callback_function));
        bool invoke_callback = false;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            if (state_->requested.load(std::memory_order_acquire))
            {
                invoke_callback = true;
            }
            else
            {
                for (auto iterator = state_->callbacks.begin(); iterator != state_->callbacks.end();)
                {
                    if (!(*iterator)->IsActive())
                    {
                        iterator = state_->callbacks.erase(iterator);
                    }
                    else
                    {
                        ++iterator;
                    }
                }
                state_->callbacks.emplace_back(callback_state);
            }
        }
        if (invoke_callback)
        {
            callback_state->Invoke();
            return {};
        }
        return CancellationRegistration{std::move(callback_state)};
    }

  private:
    explicit CancellationToken(std::shared_ptr<detail::CancellationState> state) : state_(std::move(state)) {}

    std::shared_ptr<detail::CancellationState> state_;
    friend class CancellationSource;
};

/// Owns shared cancellation state and signals callbacks registered through its token.
///
/// Cancellation is idempotent. A source can create multiple tokens, and all
/// active callbacks registered through those tokens observe the same request.
class CancellationSource final
{
  public:
    CancellationSource() : state_(std::make_shared<detail::CancellationState>()) {}

    /// Returns a token associated with this source.
    ///
    /// @return Token that observes this source's cancellation state.
    CancellationToken GetToken() const noexcept
    {
        return CancellationToken{state_};
    }

    /// Requests cancellation and invokes each active callback once.
    ///
    /// Repeated calls have no effect. Registered callbacks must not throw.
    void RequestCancellation() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            if (state_->requested.load(std::memory_order_acquire))
            {
                return;
            }
            state_->requested.store(true, std::memory_order_release);
        }
        // RegisterCallback will not mutate this vector after observing requested under the mutex.
        for (const auto& callback : state_->callbacks)
        {
            callback->Invoke();
        }
    }

  private:
    std::shared_ptr<detail::CancellationState> state_;
};

}  // namespace score::crypto::daemon::control_plane

#endif  // SCORE_CRYPTO_SRC_DAEMON_CONTROL_PLANE_CANCELLATION_TOKEN_HPP
