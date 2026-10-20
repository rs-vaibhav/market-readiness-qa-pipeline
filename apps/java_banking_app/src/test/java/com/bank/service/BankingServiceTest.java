package com.bank.service;

import com.bank.model.Account;
import com.bank.model.Transaction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigDecimal;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Enterprise Banking Service Verification Suite")
public class BankingServiceTest {

    private BankingService service;

    @BeforeEach
    void setUp() {
        service = new BankingService();
        service.createAccount("ACC-001", "Alice Smith", "USD", new BigDecimal("1000.00"), new BigDecimal("200.00"));
        service.createAccount("ACC-002", "Bob Jones", "USD", new BigDecimal("500.00"), BigDecimal.ZERO);
    }

    @Test
    @DisplayName("Verify valid deposit increases balance and creates audit record")
    void testDepositSuccess() {
        Transaction txn = service.deposit("ACC-001", new BigDecimal("250.00"));
        assertEquals(Transaction.Status.COMPLETED, txn.getStatus());
        assertEquals(new BigDecimal("1250.00"), service.getAccount("ACC-001").getBalance());
        assertEquals(1, service.getAuditLog().size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"-50.00", "0.00"})
    @DisplayName("Verify deposit rejects non-positive amounts")
    void testDepositInvalidAmount(String amountStr) {
        assertThrows(IllegalArgumentException.class, () -> {
            service.deposit("ACC-001", new BigDecimal(amountStr));
        });
    }

    @Test
    @DisplayName("Verify valid withdrawal decreases balance")
    void testWithdrawSuccess() {
        Transaction txn = service.withdraw("ACC-001", new BigDecimal("300.00"));
        assertEquals(Transaction.Status.COMPLETED, txn.getStatus());
        assertEquals(new BigDecimal("700.00"), service.getAccount("ACC-001").getBalance());
    }

    @Test
    @DisplayName("Verify withdrawal permitted within overdraft limit")
    void testWithdrawOverdraftAllowed() {
        // Balance 1000 + Overdraft 200 = 1200 max available
        Transaction txn = service.withdraw("ACC-001", new BigDecimal("1150.00"));
        assertEquals(Transaction.Status.COMPLETED, txn.getStatus());
        assertEquals(new BigDecimal("-150.00"), service.getAccount("ACC-001").getBalance());
    }

    @Test
    @DisplayName("Verify withdrawal rejected when exceeding overdraft limit")
    void testWithdrawExceedingOverdraftBlocked() {
        assertThrows(IllegalStateException.class, () -> {
            service.withdraw("ACC-001", new BigDecimal("1250.00"));
        });
    }

    @Test
    @DisplayName("Verify atomic funds transfer between accounts")
    void testTransferSuccess() {
        Transaction txn = service.transfer("ACC-001", "ACC-002", new BigDecimal("400.00"));
        assertEquals(Transaction.Status.COMPLETED, txn.getStatus());
        assertEquals(new BigDecimal("600.00"), service.getAccount("ACC-001").getBalance());
        assertEquals(new BigDecimal("900.00"), service.getAccount("ACC-002").getBalance());
    }

    @Test
    @DisplayName("Verify transfer rejects identical source and destination")
    void testTransferSameAccountRejected() {
        assertThrows(IllegalArgumentException.class, () -> {
            service.transfer("ACC-001", "ACC-001", new BigDecimal("50.00"));
        });
    }

    @Test
    @DisplayName("Verify querying nonexistent account raises NoSuchElementException")
    void testNonexistentAccount() {
        assertThrows(NoSuchElementException.class, () -> {
            service.getAccount("ACC-999");
        });
    }

    @Test
    @DisplayName("Verify fraud detection marks transactions at or above threshold as high-risk")
    void testHighRiskDetection() {
        assertTrue(service.isHighRiskTransaction(new BigDecimal("50000.00")));
        assertTrue(service.isHighRiskTransaction(new BigDecimal("100000.00")));
        assertFalse(service.isHighRiskTransaction(new BigDecimal("49999.99")));
    }
}
