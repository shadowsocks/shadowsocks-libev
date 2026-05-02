#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "json.h"

static void
test_parse_simple_object(void)
{
    const char *json_str = "{\"key\": \"value\", \"num\": 42}";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_object);
    assert(val->u.object.length == 2);

    /* Check first entry */
    assert(strcmp(val->u.object.values[0].name, "key") == 0);
    assert(val->u.object.values[0].value->type == json_string);
    assert(strcmp(val->u.object.values[0].value->u.string.ptr, "value") == 0);

    /* Check second entry */
    assert(strcmp(val->u.object.values[1].name, "num") == 0);
    assert(val->u.object.values[1].value->type == json_integer);
    assert(val->u.object.values[1].value->u.integer == 42);

    json_value_free(val);
}

static void
test_parse_array(void)
{
    const char *json_str = "[1, 2, 3]";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_array);
    assert(val->u.array.length == 3);
    assert(val->u.array.values[0]->type == json_integer);
    assert(val->u.array.values[0]->u.integer == 1);
    assert(val->u.array.values[1]->u.integer == 2);
    assert(val->u.array.values[2]->u.integer == 3);

    json_value_free(val);
}

static void
test_parse_nested(void)
{
    const char *json_str = "{\"outer\": {\"inner\": true}}";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_object);
    assert(val->u.object.length == 1);

    json_value *outer = val->u.object.values[0].value;
    assert(outer->type == json_object);
    assert(outer->u.object.length == 1);

    assert(outer->u.object.values[0].value->type == json_boolean);
    assert(outer->u.object.values[0].value->u.boolean != 0);

    json_value_free(val);
}

static void
test_parse_types(void)
{
    const char *json_str = "{\"s\": \"hello\", \"i\": -5, \"d\": 3.14, \"b\": false, \"n\": null}";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_object);
    assert(val->u.object.length == 5);

    assert(val->u.object.values[0].value->type == json_string);
    assert(val->u.object.values[1].value->type == json_integer);
    assert(val->u.object.values[1].value->u.integer == -5);
    assert(val->u.object.values[2].value->type == json_double);
    assert(val->u.object.values[3].value->type == json_boolean);
    assert(val->u.object.values[3].value->u.boolean == 0);
    assert(val->u.object.values[4].value->type == json_null);

    json_value_free(val);
}

static void
test_parse_invalid(void)
{
    /* Missing closing brace */
    assert(json_parse("{\"key\": 1", 9) == NULL);

    /* Empty string */
    assert(json_parse("", 0) == NULL);

    /* Just garbage */
    assert(json_parse("not json", 8) == NULL);
}

static void
test_parse_empty_object(void)
{
    const char *json_str = "{}";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_object);
    assert(val->u.object.length == 0);
    json_value_free(val);
}

static void
test_parse_empty_array(void)
{
    const char *json_str = "[]";
    json_value *val = json_parse(json_str, strlen(json_str));
    assert(val != NULL);
    assert(val->type == json_array);
    assert(val->u.array.length == 0);
    json_value_free(val);
}

int
main(void)
{
    test_parse_simple_object();
    test_parse_array();
    test_parse_nested();
    test_parse_types();
    test_parse_invalid();
    test_parse_empty_object();
    test_parse_empty_array();
    return 0;
}
