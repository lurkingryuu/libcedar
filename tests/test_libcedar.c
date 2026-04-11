/*
 * test_libcedar.c — Smoke test for the libcedar C bindings
 *
 * Compile:
 *   cc -o test_libcedar test_libcedar.c $(pkg-config --cflags --libs libcedar)
 *
 * Run:
 *   LD_LIBRARY_PATH=/usr/local/lib ./test_libcedar
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libcedar.h"

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
        exit(1); \
    } \
} while (0)

#define PASS(name) printf("  PASS: %s\n", name)

static void test_lifecycle(void) {
    CedarEngine *engine = cedar_engine_new();
    ASSERT(engine != NULL, "engine should not be NULL");
    cedar_engine_free(engine);
    PASS("lifecycle");
}

static void test_free_null(void) {
    cedar_engine_free(NULL);
    PASS("free NULL");
}

static void test_simple_allow(void) {
    CedarEngine *engine = cedar_engine_new();

    int rc = cedar_engine_set_policies(engine,
        "permit(principal == User::\"alice\", action == Action::\"view\", resource == File::\"93\");");
    ASSERT(rc == 0, "set_policies should succeed");

    CedarDecision d = cedar_engine_is_authorized(engine,
        "User::\"alice\"",
        "Action::\"view\"",
        "File::\"93\"",
        NULL);
    ASSERT(d == Allow, "alice should be allowed");

    cedar_engine_free(engine);
    PASS("simple allow");
}

static void test_simple_deny(void) {
    CedarEngine *engine = cedar_engine_new();

    cedar_engine_set_policies(engine,
        "permit(principal == User::\"alice\", action == Action::\"view\", resource == File::\"93\");");

    CedarDecision d = cedar_engine_is_authorized(engine,
        "User::\"bob\"",
        "Action::\"view\"",
        "File::\"93\"",
        NULL);
    ASSERT(d == Deny, "bob should be denied");

    cedar_engine_free(engine);
    PASS("simple deny");
}

static void test_context(void) {
    CedarEngine *engine = cedar_engine_new();

    cedar_engine_set_policies(engine,
        "permit(principal, action, resource) when { context.role == \"admin\" };");

    CedarDecision d = cedar_engine_is_authorized(engine,
        "User::\"alice\"",
        "Action::\"view\"",
        "File::\"93\"",
        "{\"role\": \"admin\"}");
    ASSERT(d == Allow, "admin context should allow");

    CedarDecision d2 = cedar_engine_is_authorized(engine,
        "User::\"alice\"",
        "Action::\"view\"",
        "File::\"93\"",
        "{\"role\": \"viewer\"}");
    ASSERT(d2 == Deny, "viewer context should deny");

    cedar_engine_free(engine);
    PASS("context");
}

static void test_entities(void) {
    CedarEngine *engine = cedar_engine_new();

    cedar_engine_set_policies(engine,
        "permit(principal in Group::\"admins\", action, resource);");

    int rc = cedar_engine_set_entities_json(engine,
        "["
        "  {\"uid\": {\"type\": \"User\", \"id\": \"alice\"}, \"attrs\": {}, \"parents\": [{\"type\": \"Group\", \"id\": \"admins\"}]},"
        "  {\"uid\": {\"type\": \"Group\", \"id\": \"admins\"}, \"attrs\": {}, \"parents\": []}"
        "]");
    ASSERT(rc == 0, "set_entities should succeed");

    CedarDecision d = cedar_engine_is_authorized(engine,
        "User::\"alice\"",
        "Action::\"view\"",
        "File::\"93\"",
        NULL);
    ASSERT(d == Allow, "alice in admins group should be allowed");

    cedar_engine_free(engine);
    PASS("entities");
}

static void test_error_handling(void) {
    CedarEngine *engine = cedar_engine_new();

    int rc = cedar_engine_set_policies(engine, "not valid cedar syntax!!!");
    ASSERT(rc == -1, "bad policy should fail");

    const char *err = cedar_engine_last_error(engine);
    ASSERT(err != NULL, "should have error message");
    ASSERT(strlen(err) > 0, "error should not be empty");

    cedar_engine_clear_error(engine);
    const char *err2 = cedar_engine_last_error(engine);
    ASSERT(err2 == NULL, "error should be cleared");

    cedar_engine_free(engine);
    PASS("error handling");
}

static void test_diagnostics(void) {
    CedarEngine *engine = cedar_engine_new();

    cedar_engine_set_policies(engine,
        "permit(principal == User::\"alice\", action == Action::\"view\", resource == File::\"93\");");

    cedar_engine_is_authorized(engine,
        "User::\"alice\"",
        "Action::\"view\"",
        "File::\"93\"",
        NULL);

    const char *diag = cedar_engine_get_diagnostics(engine);
    ASSERT(diag != NULL, "should have diagnostics");
    ASSERT(strstr(diag, "reasons") != NULL, "diagnostics should contain reasons");

    cedar_engine_free(engine);
    PASS("diagnostics");
}

static void test_postgres_scenario(void) {
    CedarEngine *engine = cedar_engine_new();

    cedar_engine_set_policies(engine,
        "permit(principal == User::\"alice\", action == Action::\"SELECT\", resource);\n"
        "forbid(principal == User::\"bob\", action, resource);\n");

    /* alice SELECT → allow */
    CedarDecision d1 = cedar_engine_is_authorized(engine,
        "User::\"alice\"",
        "Action::\"SELECT\"",
        "Table::\"public.employees\"",
        "{\"day\":\"mon\",\"date\":20260224}");
    ASSERT(d1 == Allow, "alice SELECT should be allowed");

    /* bob SELECT → deny */
    CedarDecision d2 = cedar_engine_is_authorized(engine,
        "User::\"bob\"",
        "Action::\"SELECT\"",
        "Table::\"public.employees\"",
        "{\"day\":\"mon\",\"date\":20260224}");
    ASSERT(d2 == Deny, "bob SELECT should be denied");

    cedar_engine_free(engine);
    PASS("postgres scenario");
}

/* ============================================================
 * NEW TESTS — extended coverage
 * ============================================================ */

/* Schema JSON matching the PostgreSQL section of schema.json */
static const char *PG_SCHEMA_JSON =
    "{"
    "  \"PostgreSQL\": {"
    "    \"entityTypes\": {"
    "      \"User\":    { \"shape\": { \"type\": \"Record\", \"attributes\": {} } },"
    "      \"Table\":   { \"shape\": { \"type\": \"Record\", \"attributes\": {} } },"
    "      \"Column\":  { \"shape\": { \"type\": \"Record\", \"attributes\": {} } },"
    "      \"Schema\":  { \"shape\": { \"type\": \"Record\", \"attributes\": {} } },"
    "      \"Routine\": { \"shape\": { \"type\": \"Record\", \"attributes\": {} } }"
    "    },"
    "    \"actions\": {"
    "      \"SELECT\":   { \"appliesTo\": { \"principalTypes\": [\"User\"], \"resourceTypes\": [\"Table\", \"Column\"] } },"
    "      \"INSERT\":   { \"appliesTo\": { \"principalTypes\": [\"User\"], \"resourceTypes\": [\"Table\"] } },"
    "      \"UPDATE\":   { \"appliesTo\": { \"principalTypes\": [\"User\"], \"resourceTypes\": [\"Table\"] } },"
    "      \"DELETE\":   { \"appliesTo\": { \"principalTypes\": [\"User\"], \"resourceTypes\": [\"Table\"] } },"
    "      \"TRUNCATE\": { \"appliesTo\": { \"principalTypes\": [\"User\"], \"resourceTypes\": [\"Table\"] } },"
    "      \"EXECUTE\":  { \"appliesTo\": { \"principalTypes\": [\"User\"], \"resourceTypes\": [\"Routine\"] } },"
    "      \"USAGE\":    { \"appliesTo\": { \"principalTypes\": [\"User\"], \"resourceTypes\": [\"Schema\"] } }"
    "    }"
    "  }"
    "}";

static void test_schema_validation_valid(void) {
    CedarEngine *engine = cedar_engine_new();

    /* Load policies that conform to the schema */
    int rc = cedar_engine_set_policies(engine,
        "permit(principal == PostgreSQL::User::\"alice\","
        "       action   == PostgreSQL::Action::\"SELECT\","
        "       resource == PostgreSQL::Table::\"public.items\");");
    ASSERT(rc == 0, "set_policies should succeed");

    rc = cedar_engine_set_schema_json(engine, PG_SCHEMA_JSON);
    ASSERT(rc == 0, "set_schema_json should succeed");

    rc = cedar_engine_validate(engine);
    ASSERT(rc == 0, "validate should pass for conforming policies");

    cedar_engine_free(engine);
    PASS("schema validation (valid policies)");
}

static void test_schema_validation_wrong_resource_type(void) {
    CedarEngine *engine = cedar_engine_new();

    /* INSERT on Schema violates schema (INSERT only applies to Table) */
    cedar_engine_set_policies(engine,
        "permit(principal == PostgreSQL::User::\"alice\","
        "       action   == PostgreSQL::Action::\"INSERT\","
        "       resource == PostgreSQL::Schema::\"public\");");

    cedar_engine_set_schema_json(engine, PG_SCHEMA_JSON);

    int rc = cedar_engine_validate(engine);
    ASSERT(rc != 0, "validate should fail when resource type is wrong");

    const char *err = cedar_engine_last_error(engine);
    ASSERT(err != NULL && strlen(err) > 0, "should have non-empty validation error");

    cedar_engine_free(engine);
    PASS("schema validation (wrong resource type caught)");
}

static void test_schema_null_clears_schema(void) {
    CedarEngine *engine = cedar_engine_new();

    cedar_engine_set_schema_json(engine, PG_SCHEMA_JSON);

    /* NULL clears the schema */
    int rc = cedar_engine_set_schema_json(engine, NULL);
    ASSERT(rc == 0, "setting NULL schema should succeed");

    /* Load a policy that would fail schema validation if schema were present */
    cedar_engine_set_policies(engine,
        "permit(principal == PostgreSQL::User::\"alice\","
        "       action   == PostgreSQL::Action::\"INSERT\","
        "       resource == PostgreSQL::Schema::\"public\");");

    /* Without schema, validate() passes (nothing to validate against) */
    rc = cedar_engine_validate(engine);
    ASSERT(rc == 0, "validate without schema should return 0");

    cedar_engine_free(engine);
    PASS("schema null clears schema");
}

static void test_forbid_overrides_permit(void) {
    CedarEngine *engine = cedar_engine_new();

    /* Broad permit + specific forbid */
    cedar_engine_set_policies(engine,
        "permit(principal, action, resource);\n"
        "forbid(principal == User::\"alice\", action == Action::\"DELETE\", resource);\n");

    /* alice can view (permit matches, no forbid) */
    CedarDecision d1 = cedar_engine_is_authorized(engine,
        "User::\"alice\"", "Action::\"view\"", "File::\"x\"", NULL);
    ASSERT(d1 == Allow, "alice view should be allowed");

    /* alice cannot DELETE (forbid overrides permit) */
    CedarDecision d2 = cedar_engine_is_authorized(engine,
        "User::\"alice\"", "Action::\"DELETE\"", "File::\"x\"", NULL);
    ASSERT(d2 == Deny, "alice DELETE should be denied by forbid");

    cedar_engine_free(engine);
    PASS("forbid overrides permit");
}

static void test_deep_entity_hierarchy(void) {
    CedarEngine *engine = cedar_engine_new();

    /* Policy: grant if principal is in Org::"acme" (3 levels away) */
    cedar_engine_set_policies(engine,
        "permit(principal in Org::\"acme\", action, resource);");

    /* alice → team_a → dept_eng → Org::"acme" */
    int rc = cedar_engine_set_entities_json(engine,
        "["
        "  {\"uid\":{\"type\":\"User\",       \"id\":\"alice\"},  \"attrs\":{}, \"parents\":[{\"type\":\"Team\",       \"id\":\"team_a\"}]},"
        "  {\"uid\":{\"type\":\"Team\",       \"id\":\"team_a\"}, \"attrs\":{}, \"parents\":[{\"type\":\"Department\", \"id\":\"eng\"}]},"
        "  {\"uid\":{\"type\":\"Department\", \"id\":\"eng\"},    \"attrs\":{}, \"parents\":[{\"type\":\"Org\",        \"id\":\"acme\"}]},"
        "  {\"uid\":{\"type\":\"Org\",        \"id\":\"acme\"},   \"attrs\":{}, \"parents\":[]}"
        "]");
    ASSERT(rc == 0, "set_entities should succeed");

    CedarDecision d = cedar_engine_is_authorized(engine,
        "User::\"alice\"", "Action::\"view\"", "File::\"x\"", NULL);
    ASSERT(d == Allow, "alice should be allowed via 3-level transitive hierarchy");

    cedar_engine_free(engine);
    PASS("deep entity hierarchy (transitive)");
}

static void test_clear_entities(void) {
    CedarEngine *engine = cedar_engine_new();

    cedar_engine_set_policies(engine,
        "permit(principal in Group::\"admins\", action, resource);");

    cedar_engine_set_entities_json(engine,
        "["
        "  {\"uid\":{\"type\":\"User\",  \"id\":\"alice\"},  \"attrs\":{}, \"parents\":[{\"type\":\"Group\",\"id\":\"admins\"}]},"
        "  {\"uid\":{\"type\":\"Group\", \"id\":\"admins\"}, \"attrs\":{}, \"parents\":[]}"
        "]");

    /* Before clear: allowed */
    CedarDecision d1 = cedar_engine_is_authorized(engine,
        "User::\"alice\"", "Action::\"do\"", "File::\"f\"", NULL);
    ASSERT(d1 == Allow, "before clear: alice should be allowed");

    cedar_engine_clear_entities(engine);

    /* After clear: denied (entity hierarchy gone) */
    CedarDecision d2 = cedar_engine_is_authorized(engine,
        "User::\"alice\"", "Action::\"do\"", "File::\"f\"", NULL);
    ASSERT(d2 == Deny, "after clear: alice should be denied");

    cedar_engine_free(engine);
    PASS("clear_entities removes hierarchy");
}

static void test_empty_policy_set_denies_all(void) {
    CedarEngine *engine = cedar_engine_new();

    int rc = cedar_engine_set_policies(engine, "");
    ASSERT(rc == 0, "empty policy string should succeed");

    CedarDecision d = cedar_engine_is_authorized(engine,
        "User::\"alice\"", "Action::\"view\"", "File::\"x\"", NULL);
    ASSERT(d == Deny, "empty policy set should deny all requests");

    cedar_engine_free(engine);
    PASS("empty policy set denies all");
}

static void test_invalid_entities_json(void) {
    CedarEngine *engine = cedar_engine_new();

    int rc = cedar_engine_set_entities_json(engine, "this is not json!!!");
    ASSERT(rc == -1, "malformed entity JSON should return -1");

    const char *err = cedar_engine_last_error(engine);
    ASSERT(err != NULL && strlen(err) > 0, "should have non-empty error after malformed entities");

    /* Engine should still be usable after the error */
    cedar_engine_clear_error(engine);
    cedar_engine_set_policies(engine,
        "permit(principal == User::\"alice\", action, resource);");
    CedarDecision d = cedar_engine_is_authorized(engine,
        "User::\"alice\"", "Action::\"view\"", "File::\"x\"", NULL);
    ASSERT(d == Allow, "engine should be usable after entity parse error");

    cedar_engine_free(engine);
    PASS("invalid entities JSON: error + recovery");
}

static void test_set_policies_replaces_previous(void) {
    CedarEngine *engine = cedar_engine_new();

    /* First policy: only alice */
    cedar_engine_set_policies(engine,
        "permit(principal == User::\"alice\", action, resource);");

    /* Replace with policy: only bob */
    int rc = cedar_engine_set_policies(engine,
        "permit(principal == User::\"bob\", action, resource);");
    ASSERT(rc == 0, "second set_policies should succeed");

    /* alice must now be denied (first policy was replaced) */
    CedarDecision d_alice = cedar_engine_is_authorized(engine,
        "User::\"alice\"", "Action::\"view\"", "File::\"x\"", NULL);
    ASSERT(d_alice == Deny, "alice should be denied after policy replacement");

    /* bob must now be allowed */
    CedarDecision d_bob = cedar_engine_is_authorized(engine,
        "User::\"bob\"", "Action::\"view\"", "File::\"x\"", NULL);
    ASSERT(d_bob == Allow, "bob should be allowed after policy replacement");

    cedar_engine_free(engine);
    PASS("set_policies replaces previous policy set");
}

static void test_multiple_engines_independent(void) {
    CedarEngine *engine_a = cedar_engine_new();
    CedarEngine *engine_b = cedar_engine_new();

    cedar_engine_set_policies(engine_a,
        "permit(principal == User::\"alice\", action, resource);");
    cedar_engine_set_policies(engine_b,
        "permit(principal == User::\"bob\", action, resource);");

    CedarDecision da_alice = cedar_engine_is_authorized(engine_a,
        "User::\"alice\"", "Action::\"view\"", "File::\"x\"", NULL);
    CedarDecision da_bob   = cedar_engine_is_authorized(engine_a,
        "User::\"bob\"", "Action::\"view\"", "File::\"x\"", NULL);
    CedarDecision db_alice = cedar_engine_is_authorized(engine_b,
        "User::\"alice\"", "Action::\"view\"", "File::\"x\"", NULL);
    CedarDecision db_bob   = cedar_engine_is_authorized(engine_b,
        "User::\"bob\"", "Action::\"view\"", "File::\"x\"", NULL);

    ASSERT(da_alice == Allow, "engine_a: alice → Allow");
    ASSERT(da_bob   == Deny,  "engine_a: bob   → Deny");
    ASSERT(db_alice == Deny,  "engine_b: alice → Deny");
    ASSERT(db_bob   == Allow, "engine_b: bob   → Allow");

    cedar_engine_free(engine_a);
    cedar_engine_free(engine_b);
    PASS("multiple independent engines");
}

static void test_all_postgres_schema_actions(void) {
    CedarEngine *engine = cedar_engine_new();

    cedar_engine_set_policies(engine,
        "permit(principal == User::\"alice\", action == Action::\"SELECT\",   resource == Table::\"public.items\");\n"
        "permit(principal == User::\"alice\", action == Action::\"INSERT\",   resource == Table::\"public.items\");\n"
        "permit(principal == User::\"alice\", action == Action::\"UPDATE\",   resource == Table::\"public.items\");\n"
        "permit(principal == User::\"alice\", action == Action::\"DELETE\",   resource == Table::\"public.items\");\n"
        "permit(principal == User::\"alice\", action == Action::\"TRUNCATE\", resource == Table::\"public.items\");\n"
        "permit(principal == User::\"alice\", action == Action::\"SELECT\",   resource == Column::\"public.items.id\");\n"
        "permit(principal == User::\"alice\", action == Action::\"EXECUTE\",  resource == Routine::\"get_value\");\n"
        "permit(principal == User::\"alice\", action == Action::\"USAGE\",    resource == Schema::\"public\");\n");

    struct { const char *action; const char *resource; } cases[] = {
        { "Action::\"SELECT\"",   "Table::\"public.items\""     },
        { "Action::\"INSERT\"",   "Table::\"public.items\""     },
        { "Action::\"UPDATE\"",   "Table::\"public.items\""     },
        { "Action::\"DELETE\"",   "Table::\"public.items\""     },
        { "Action::\"TRUNCATE\"", "Table::\"public.items\""     },
        { "Action::\"SELECT\"",   "Column::\"public.items.id\"" },
        { "Action::\"EXECUTE\"",  "Routine::\"get_value\""      },
        { "Action::\"USAGE\"",    "Schema::\"public\""          },
    };
    int n = sizeof(cases) / sizeof(cases[0]);

    for (int i = 0; i < n; i++) {
        CedarDecision d_alice = cedar_engine_is_authorized(engine,
            "User::\"alice\"", cases[i].action, cases[i].resource, NULL);
        ASSERT(d_alice == Allow, "alice should be allowed for each action");

        CedarDecision d_bob = cedar_engine_is_authorized(engine,
            "User::\"bob\"", cases[i].action, cases[i].resource, NULL);
        ASSERT(d_bob == Deny, "bob should be denied for each action");
    }

    cedar_engine_free(engine);
    PASS("all PostgreSQL schema.json actions (allow alice / deny bob)");
}

static void test_namespace_uids(void) {
    /* Test Cedar namespace-prefixed UIDs (e.g. PG::User::"alice") */
    CedarEngine *engine = cedar_engine_new();

    cedar_engine_set_policies(engine,
        "permit(principal == PG::User::\"alice\","
        "       action   == PG::Action::\"SELECT\","
        "       resource == PG::Table::\"public.items\");");

    /* Namespaced principal/action/resource → Allow */
    CedarDecision d1 = cedar_engine_is_authorized(engine,
        "PG::User::\"alice\"",
        "PG::Action::\"SELECT\"",
        "PG::Table::\"public.items\"",
        NULL);
    ASSERT(d1 == Allow, "namespaced UIDs should match namespaced policy → Allow");

    /* Non-namespaced principal → Deny (different entity type) */
    CedarDecision d2 = cedar_engine_is_authorized(engine,
        "User::\"alice\"",
        "Action::\"SELECT\"",
        "Table::\"public.items\"",
        NULL);
    ASSERT(d2 == Deny, "non-namespaced UIDs should not match namespaced policy → Deny");

    cedar_engine_free(engine);
    PASS("namespace-prefixed Cedar UIDs");
}

static void test_validate_without_schema(void) {
    CedarEngine *engine = cedar_engine_new();

    cedar_engine_set_policies(engine,
        "permit(principal == User::\"alice\", action, resource);");

    /* validate() with no schema loaded should return 0 */
    int rc = cedar_engine_validate(engine);
    ASSERT(rc == 0, "validate without schema should return 0");

    cedar_engine_free(engine);
    PASS("validate without schema returns 0");
}

static void test_context_day_gating(void) {
    CedarEngine *engine = cedar_engine_new();

    cedar_engine_set_policies(engine,
        "permit(principal == User::\"alice\", action == Action::\"SELECT\", resource)"
        "  when { context.day == \"mon\" || context.day == \"tue\" || context.day == \"wed\" ||"
        "         context.day == \"thu\" || context.day == \"fri\" };");

    CedarDecision weekday = cedar_engine_is_authorized(engine,
        "User::\"alice\"", "Action::\"SELECT\"", "Table::\"t\"",
        "{\"day\":\"wed\",\"date\":20260304}");
    ASSERT(weekday == Allow, "weekday context should allow");

    CedarDecision weekend = cedar_engine_is_authorized(engine,
        "User::\"alice\"", "Action::\"SELECT\"", "Table::\"t\"",
        "{\"day\":\"sat\",\"date\":20260307}");
    ASSERT(weekend == Deny, "weekend context should deny");

    cedar_engine_free(engine);
    PASS("context day-gating policy");
}

int main(void) {
    printf("libcedar C test suite\n");
    printf("=====================\n");

    /* Original tests */
    test_lifecycle();
    test_free_null();
    test_simple_allow();
    test_simple_deny();
    test_context();
    test_entities();
    test_error_handling();
    test_diagnostics();
    test_postgres_scenario();

    /* Extended tests */
    test_schema_validation_valid();
    test_schema_validation_wrong_resource_type();
    test_schema_null_clears_schema();
    test_forbid_overrides_permit();
    test_deep_entity_hierarchy();
    test_clear_entities();
    test_empty_policy_set_denies_all();
    test_invalid_entities_json();
    test_set_policies_replaces_previous();
    test_multiple_engines_independent();
    test_all_postgres_schema_actions();
    test_namespace_uids();
    test_validate_without_schema();
    test_context_day_gating();

    printf("\nAll tests passed!\n");
    return 0;
}
