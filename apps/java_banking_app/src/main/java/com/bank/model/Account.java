package com.bank.model;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Objects;

/**
 * Enterprise Banking Account Entity.
 * Maintains immutable audit logs and currency-accurate balances using BigDecimal.
 */
public class Account {
    private final String accountNumber;
    private final String accountHolder;
    private final String currency;
    private BigDecimal balance;
    private BigDecimal overdraftLimit;
    private boolean active;
    private final Instant createdAt;

    public Account(String accountNumber, String accountHolder, String currency, BigDecimal initialBalance, BigDecimal overdraftLimit) {
        if (accountNumber == null || accountNumber.trim().isEmpty()) {
            throw new IllegalArgumentException("Account number cannot be null or empty");
        }
        if (accountHolder == null || accountHolder.trim().isEmpty()) {
            throw new IllegalArgumentException("Account holder name cannot be null or empty");
        }
        if (initialBalance == null || initialBalance.compareTo(BigDecimal.ZERO) < 0) {
            throw new IllegalArgumentException("Initial balance cannot be negative");
        }
        this.accountNumber = accountNumber.trim();
        this.accountHolder = accountHolder.trim();
        this.currency = (currency != null) ? currency.toUpperCase() : "USD";
        this.balance = initialBalance;
        this.overdraftLimit = (overdraftLimit != null && overdraftLimit.compareTo(BigDecimal.ZERO) >= 0)
                ? overdraftLimit : BigDecimal.ZERO;
        this.active = true;
        this.createdAt = Instant.now();
    }

    public synchronized void credit(BigDecimal amount) {
        if (!active) {
            throw new IllegalStateException("Account is inactive");
        }
        if (amount == null || amount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Credit amount must be positive");
        }
        this.balance = this.balance.add(amount);
    }

    public synchronized void debit(BigDecimal amount) {
        if (!active) {
            throw new IllegalStateException("Account is inactive");
        }
        if (amount == null || amount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Debit amount must be positive");
        }
        BigDecimal maxAvailable = this.balance.add(this.overdraftLimit);
        if (amount.compareTo(maxAvailable) > 0) {
            throw new IllegalStateException(
                String.format("Insufficient funds. Available: %s, Requested: %s", maxAvailable, amount)
            );
        }
        this.balance = this.balance.subtract(amount);
    }

    public String getAccountNumber() { return accountNumber; }
    public String getAccountHolder() { return accountHolder; }
    public String getCurrency() { return currency; }
    public synchronized BigDecimal getBalance() { return balance; }
    public synchronized BigDecimal getOverdraftLimit() { return overdraftLimit; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public Instant getCreatedAt() { return createdAt; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Account)) return false;
        Account account = (Account) o;
        return Objects.equals(accountNumber, account.accountNumber);
    }

    @Override
    public int hashCode() {
        return Objects.hash(accountNumber);
    }
}
