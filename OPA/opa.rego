package barmanagement

default allow := false

allow {
    input_action := lower(input.resources.attributes.action)
    input_controller := lower(input.resources.attributes.controller)
    logical_action := determine_action(input_action, input_controller)
    logical_action == "OrderDrink"
    access_allowed_order_drink
} else {
    logical_action := determine_action(lower(input.resources.attributes.action), lower(input.resources.attributes.controller))
    logical_action == "AddDrink"
    access_allowed_add_drink
}

determine_action(action, controller) = result {
    action == "post"
    controller == "bar"
    result := "OrderDrink"
} else = result {
    action == "post"
    controller == "managebar"
    result := "AddDrink"
} else = "Unknown" {
    result := "Unknown"
}

access_allowed_order_drink {
    age := get_age_from_jwt
    drink_name := input.request.body.DrinkName
    lower_drink_name := lower(drink_name)
    lower_drink_name != "beer"
}

access_allowed_order_drink {
    age := get_age_from_jwt
    drink_name := input.request.body.DrinkName
    lower_drink_name := lower(drink_name)
    lower_drink_name == "beer"
    to_number(age) >= 16
}

access_allowed_add_drink {
    roles := get_roles_from_jwt
    "bartender" == roles[_]
}

get_age_from_jwt := age {
    auth_header := input.request.headers.Authorization
    token := substring(auth_header, count("Bearer "), -1)
    [_, payload, _] := io.jwt.decode(token)
    age := payload.age
}

get_roles_from_jwt := roles {
    auth_header := input.request.headers.Authorization
    token := substring(auth_header, count("Bearer "), -1)
    [_, payload, _] := io.jwt.decode(token)
    roles := payload.role
}