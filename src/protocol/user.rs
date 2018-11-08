use general_derive::{FromValue, ProcessValue, ToValue};

use super::*;

/// Geographical location of the end user or device.
#[derive(Debug, Clone, PartialEq, Default, FromValue, ToValue, ProcessValue)]
#[metastructure(process_func = "process_geo")]
pub struct Geo {
    /// Two-letter country code (ISO 3166-1 alpha-2).
    #[metastructure(pii_kind = "location", cap_size = "summary")]
    pub country_code: Annotated<String>,

    /// Human readable city name.
    #[metastructure(pii_kind = "location", cap_size = "summary")]
    pub city: Annotated<String>,

    /// Human readable region name or code.
    #[metastructure(pii_kind = "location", cap_size = "summary")]
    pub region: Annotated<String>,

    /// Additional arbitrary fields for forwards compatibility.
    #[metastructure(additional_properties)]
    pub other: Object<Value>,
}

/// Information about the user who triggered an event.
#[derive(Debug, Clone, PartialEq, Default, FromValue, ToValue, ProcessValue)]
#[metastructure(process_func = "process_user")]
pub struct User {
    /// Unique identifier of the user.
    #[metastructure(pii_kind = "id", cap_size = "enumlike")]
    pub id: Annotated<String>,

    /// Email address of the user.
    #[metastructure(pii_kind = "email", cap_size = "email")]
    pub email: Annotated<String>,

    /// Remote IP address of the user. Defaults to "{{auto}}".
    #[metastructure(pii_kind = "ip")]
    pub ip_address: Annotated<IpAddr>,

    /// Username of the user.
    #[metastructure(pii_kind = "username", cap_size = "enumlike")]
    pub username: Annotated<String>,

    /// Human readable name of the user.
    #[metastructure(pii_kind = "name", cap_size = "enumlike")]
    pub name: Annotated<String>,

    /// Approximate geographical location of the end user or device.
    pub geo: Annotated<Geo>,

    /// Additional arbitrary fields for forwards compatibility.
    #[metastructure(additional_properties, pii_kind = "databag")]
    pub other: Object<Value>,
}

#[test]
fn test_geo_roundtrip() {
    let json = r#"{
  "country_code": "US",
  "city": "San Francisco",
  "region": "CA",
  "other": "value"
}"#;
    let geo = Annotated::new(Geo {
        country_code: Annotated::new("US".to_string()),
        city: Annotated::new("San Francisco".to_string()),
        region: Annotated::new("CA".to_string()),
        other: {
            let mut map = Map::new();
            map.insert(
                "other".to_string(),
                Annotated::new(Value::String("value".to_string())),
            );
            map
        },
    });

    assert_eq_dbg!(geo, Annotated::from_json(json).unwrap());
    assert_eq_str!(json, geo.to_json_pretty().unwrap());
}

#[test]
fn test_geo_default_values() {
    let json = "{}";
    let geo = Annotated::new(Geo {
        country_code: Annotated::empty(),
        city: Annotated::empty(),
        region: Annotated::empty(),
        other: Default::default(),
    });

    assert_eq_dbg!(geo, Annotated::from_json(json).unwrap());
    assert_eq_str!(json, geo.to_json_pretty().unwrap());
}

#[test]
fn test_user_roundtrip() {
    let json = r#"{
  "id": "e4e24881-8238-4539-a32b-d3c3ecd40568",
  "email": "mail@example.org",
  "ip_address": "{{auto}}",
  "username": "john_doe",
  "name": "John Doe",
  "other": "value"
}"#;
    let user = Annotated::new(User {
        id: Annotated::new("e4e24881-8238-4539-a32b-d3c3ecd40568".to_string()),
        email: Annotated::new("mail@example.org".to_string()),
        ip_address: Annotated::new(IpAddr::auto()),
        name: Annotated::new("John Doe".to_string()),
        username: Annotated::new("john_doe".to_string()),
        geo: Annotated::empty(),
        other: {
            let mut map = Object::new();
            map.insert(
                "other".to_string(),
                Annotated::new(Value::String("value".to_string())),
            );
            map
        },
    });

    assert_eq_dbg!(user, Annotated::from_json(json).unwrap());
    assert_eq_str!(json, user.to_json_pretty().unwrap());
}
