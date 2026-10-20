package com.bank.model;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * Audit-compliant financial transaction record.
 */
public class Transaction {
    public enum Type { DEPOSIT, WITHDRAWAL, TRANSFER }
    public enum Status { PENDING, COMPLETED, FAILED }

    private final String transactionId;
    private final String sourceAccount;
    private final String destinationAccount;
    private final BigDecimal amount;
    private final Type type;
    private Status status;
    private final Instant timestamp;

    public Transaction(String sourceAccount, String destinationAccount, BigDecimal amount, Type type) {
        this.transactionId = "TXN-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        this.sourceAccount = sourceAccount;
        this.destinationAccount = destinationAccount;
        this.amount = amount;
        this.type = type;
        this.status = Status.PENDING;
        this.timestamp = Instant.now();
    }

    public String getTransactionId() { return transactionId; }
    public String getSourceAccount() { return sourceAccount; }
    public String getDestinationAccount() { return destinationAccount; }
    public BigDecimal getAmount() { return amount; }
    public Type getType() { return type; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public Instant getTimestamp() { return timestamp; }
}
