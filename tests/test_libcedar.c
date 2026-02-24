/*
 * test_libcedar.c — Smoke test for the libcedar C bindings
 *
 * Compile:
 *   cc -o test_libcedar test_libcedar.c \
 *      -I../include -L../target/release -lcedar \
 *      -framework Security -framework CoreFoundation -lresolv
 *
 * Run:
 *   ./test_libcedar
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

int main(void) {
    printf("libcedar C test suite\n");
    printf("=====================\n");

    test_lifecycle();
    test_free_null();
    test_simple_allow();
    test_simple_deny();
    test_context();
    test_entities();
    test_error_handling();
    test_diagnostics();
    test_postgres_scenario();

    printf("\nAll tests passed!\n");
    return 0;
}
