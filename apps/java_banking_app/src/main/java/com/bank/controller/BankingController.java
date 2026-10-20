package com.bank.controller;

import com.bank.model.Account;
import com.bank.model.Transaction;
import com.bank.service.BankingService;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;

/**
 * REST API Controller mapping HTTP operations for banking lifecycle.
 */
public class BankingController {
    private final BankingService bankingService;

    public BankingController(BankingService bankingService) {
        this.bankingService = bankingService;
    }

    public Map<String, Object> handleGetBalance(String accountNumber) {
        Map<String, Object> response = new HashMap<>();
        try {
            Account account = bankingService.getAccount(accountNumber);
            response.put("status", "SUCCESS");
            response.put("accountNumber", account.getAccountNumber());
            response.put("balance", account.getBalance().toPlainString());
            response.put("currency", account.getCurrency());
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", e.getMessage());
        }
        return response;
    }

    public Map<String, Object> handleTransfer(String fromAcc, String toAcc, String amountStr) {
        Map<String, Object> response = new HashMap<>();
        try {
            BigDecimal amount = new BigDecimal(amountStr);
            Transaction txn = bankingService.transfer(fromAcc, toAcc, amount);
            response.put("status", "SUCCESS");
            response.put("transactionId", txn.getTransactionId());
            response.put("amount", txn.getAmount().toPlainString());
            response.put("highRisk", bankingService.isHighRiskTransaction(amount));
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("message", e.getMessage());
        }
        return response;
    }
}
