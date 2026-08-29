package com.example.rbac.business;

import com.example.rbac.business.DataScopePolicyClient.Policy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Verifies that every business endpoint applies the data scope policy in SQL,
 * so a user can never read another tenant's or another department's documents.
 */
class BusinessControllerDataScopeTest {
    private JdbcTemplate jdbc;
    private DataScopePolicyClient policyClient;
    private BusinessController controller;

    @BeforeEach
    void setUp() {
        DataSource ds = new DriverManagerDataSource("jdbc:h2:mem:rbac;MODE=MySQL;DB_CLOSE_DELAY=-1", "sa", "");
        jdbc = new JdbcTemplate(ds);
        jdbc.execute("DROP TABLE IF EXISTS biz_document");
        jdbc.execute("CREATE TABLE biz_document (id BIGINT PRIMARY KEY, title VARCHAR(255), owner_user_id BIGINT, org_unit_id BIGINT, tenant_id VARCHAR(64), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
        seedDocument(1L, "T1-RD-1", 7L, 2L, "T1");
        seedDocument(2L, "T1-SALES-1", 8L, 3L, "T1");
        seedDocument(3L, "T1-SELF-7", 7L, 1L, "T1");
        seedDocument(4L, "T2-RD-1", 9L, 2L, "T2");
        seedDocument(5L, "T2-SELF-7", 7L, 4L, "T2");
        policyClient = mock(DataScopePolicyClient.class);
        controller = new BusinessController(jdbc, policyClient);
    }

    private void seedDocument(long id, String title, long owner, long org, String tenant) {
        jdbc.update("INSERT INTO biz_document(id, title, owner_user_id, org_unit_id, tenant_id) VALUES (?, ?, ?, ?, ?)", id, title, owner, org, tenant);
    }

    @Test
    void departmentAndDescendantsCannotReadSiblingDepartmentOrOtherTenant() {
        Policy policy = new Policy(false, false, Set.of(1L, 2L), Set.of("T1"));
        when(policyClient.policy(7L)).thenReturn(policy);

        BusinessController.Page<BusinessController.DocumentView> page = controller.documents(7L, 0, 50).data();
        assertEquals(2, page.total());
        List<Long> ids = page.items().stream().map(BusinessController.DocumentView::id).toList();
        assertTrue(ids.containsAll(List.of(1L, 3L)));
        assertTrue(ids.stream().noneMatch(id -> id == 2L), "T1-SALES 兄弟部门不得返回");
        assertTrue(ids.stream().noneMatch(id -> id == 5L), "T2 租户文档不得返回");
    }

    @Test
    void selfScopeNeverLeaksOtherOwnersOrTenants() {
        when(policyClient.policy(7L)).thenReturn(new Policy(false, true, Set.of(), Set.of("T1")));

        var page = controller.documents(7L, 0, 50).data();
        assertEquals(2, page.total());
        var ids = page.items().stream().map(BusinessController.DocumentView::id).toList();
        assertTrue(ids.containsAll(List.of(1L, 3L)), "用户 7 在 T1 拥有文档 1 和 3");
        assertTrue(ids.stream().noneMatch(id -> id == 5L), "T2 租户文档不得返回");
    }

    @Test
    void paginationKeepsDataScopeAndTotals() {
        when(policyClient.policy(7L)).thenReturn(new Policy(false, false, Set.of(1L, 2L), Set.of("T1")));

        var page = controller.documents(7L, 0, 1).data();
        assertEquals(2, page.total());
        assertEquals(1, page.items().size());
    }

    @Test
    void batchByIdsFiltersOutOfScopeDocuments() {
        when(policyClient.policy(7L)).thenReturn(new Policy(false, false, Set.of(1L, 2L), Set.of("T1")));

        var rows = controller.batch(7L, Set.of(1L, 4L, 5L)).data();
        assertEquals(1, rows.size());
        assertEquals(1L, rows.get(0).id());
    }

    @Test
    void singleDocumentOutOfScopeReturns404() {
        when(policyClient.policy(7L)).thenReturn(new Policy(false, false, Set.of(1L, 2L), Set.of("T1")));

        assertEquals(404, controller.document(7L, 5L).code());
        assertEquals(0, controller.document(7L, 3L).code());
    }

    @Test
    void exportOnlyContainsScopedRows() {
        when(policyClient.policy(7L)).thenReturn(new Policy(false, true, Set.of(), Set.of("T1")));

        String csv = controller.exportCsv(7L);
        assertTrue(csv.contains("\"T1-SELF-7\""));
        assertTrue(!csv.contains("T2-"));
        assertTrue(!csv.contains("T1-SALES-1"));
    }

    @Test
    void asyncExportCapturesPolicyAtSubmissionTime() throws Exception {
        when(policyClient.policy(7L)).thenReturn(new Policy(false, true, Set.of(), Set.of("T1")));

        String jobId = controller.exportAsync(7L).data().get("jobId");
        for (int i = 0; i < 100 && controller.exportJob(jobId).data().status().equals("RUNNING"); i++) Thread.sleep(50);
        var view = controller.exportJob(jobId).data();
        assertEquals("COMPLETED", view.status());
        assertTrue(view.csv().contains("T1-SELF-7"));
        assertTrue(!view.csv().contains("T2-"));
    }
}
