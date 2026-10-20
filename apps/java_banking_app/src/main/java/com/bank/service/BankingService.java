package com.bank.service;

import com.bank.model.Account;
import com.bank.model.Transaction;

import java.math.BigDecimal;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Core transactional engine for deposit, withdrawal, and atomic inter-account transfer.
 */
public class BankingService {
    private final Map<String, Account> accounts = new ConcurrentHashMap<>();
    private final List<Transaction> auditLog = Collections.synchronizedList(new ArrayList<>());
    private static final BigDecimal FRAUD_THRESHOLD = new BigDecimal("50000.00");

    public Account createAccount(String accountNumber, String holder, String currency, BigDecimal initialBalance, BigDecimal overdraft) {
        if (accounts.containsKey(accountNumber)) {
            throw new IllegalArgumentException("Account " + accountNumber + " already registered");
        }
        Account account = new Account(accountNumber, holder, currency, initialBalance, overdraft);
        accounts.put(accountNumber, account);
        return account;
    }

    public Account getAccount(String accountNumber) {
        Account account = accounts.get(accountNumber);
        if (account == null) {
            throw new NoSuchElementException("Account not found: " + accountNumber);
        }
        return account;
    }

    public Transaction deposit(String accountNumber, BigDecimal amount) {
        Account account = getAccount(accountNumber);
        Transaction txn = new Transaction(null, accountNumber, amount, Transaction.Type.DEPOSIT);
        try {
            account.credit(amount);
            txn.setStatus(Transaction.Status.COMPLETED);
        } catch (Exception e) {
            txn.setStatus(Transaction.Status.FAILED);
            throw e;
        } finally {
            auditLog.add(txn);
        }
        return txn;
    }

    public Transaction withdraw(String accountNumber, BigDecimal amount) {
        Account account = getAccount(accountNumber);
        Transaction txn = new Transaction(accountNumber, null, amount, Transaction.Type.WITHDRAWAL);
        try {
            account.debit(amount);
            txn.setStatus(Transaction.Status.COMPLETED);
        } catch (Exception e) {
            txn.setStatus(Transaction.Status.FAILED);
            throw e;
        } finally {
            auditLog.add(txn);
        }
        return txn;
    }

    /**
     * Executes atomic funds transfer between two accounts to prevent deadlock and race conditions.
     */
    public Transaction transfer(String sourceAccountNumber, String destinationAccountNumber, BigDecimal amount) {
        if (sourceAccountNumber == null || destinationAccountNumber == null) {
            throw new IllegalArgumentException("Source and destination account numbers must be non-null");
        }
        if (sourceAccountNumber.equals(destinationAccountNumber)) {
            throw new IllegalArgumentException("Cannot transfer funds to the identical account");
        }

        Account source = getAccount(sourceAccountNumber);
        Account destination = getAccount(destinationAccountNumber);

        Transaction txn = new Transaction(sourceAccountNumber, destinationAccountNumber, amount, Transaction.Type.TRANSFER);

        // Enforce deadlock-free lock acquisition order
        Account firstLock = source.getAccountNumber().compareTo(destination.getAccountNumber()) < 0 ? source : destination;
        Account secondLock = (firstLock == source) ? destination : source;

        synchronized (firstLock) {
            synchronized (secondLock) {
                try {
                    source.debit(amount);
                    destination.credit(amount);
                    txn.setStatus(Transaction.Status.COMPLETED);
                } catch (Exception e) {
                    txn.setStatus(Transaction.Status.FAILED);
                    throw e;
                } finally {
                    auditLog.add(txn);
                }
            }
        }
        return txn;
    }

    public boolean isHighRiskTransaction(BigDecimal amount) {
        return amount != null && amount.compareTo(FRAUD_THRESHOLD) >= 0;
    }

    public List<Transaction> getAuditLog() {
        return Collections.unmodifiableList(new ArrayList<>(auditLog));
    }

    public int getAccountCount() {
        return accounts.size();
    }
}
