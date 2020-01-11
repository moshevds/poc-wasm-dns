mod utils;

use wasm_bindgen::prelude::*;

use wasm_bindgen::JsCast;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

fn query_as_vec(name: &str, query_type: trust_dns_proto::rr::RecordType) -> Result<std::vec::Vec<u8>, trust_dns_proto::error::ProtoError> {
    let name = trust_dns_proto::rr::Name::from_utf8(name)?;

    let query = trust_dns_proto::op::Query::query(name, query_type);

    let mut message = trust_dns_proto::op::Message::new();
    message
        .add_query(query)
        .set_id(0)
        .set_message_type(trust_dns_proto::op::MessageType::Query)
        .set_op_code(trust_dns_proto::op::OpCode::Query)
        .set_recursion_desired(true);

    message.to_vec()
}

async fn wire_with_fetch(doh_url_str: &str, request: std::vec::Vec<u8>) -> Result<std::vec::Vec<u8>, JsValue> {
    let mut opts = web_sys::RequestInit::new();
    opts.method("POST");
    opts.mode(web_sys::RequestMode::Cors);
    opts.body(Some(&(js_sys::Uint8Array::from(request.as_slice()).buffer()).into()));

    let request = web_sys::Request::new_with_str_and_init(
        doh_url_str,
        &opts,
    )?;

    request
        .headers()
        .set("Content-Type", "application/dns-message")?;
    request
        .headers()
        .set("Accept", "application/dns-message")?;

    let window = match web_sys::window() {
        Some(x) => Ok(x),
        None    => Err("window not available.")
    }?;

    let resp_value = wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&request)).await?;

    let resp: web_sys::Response = resp_value.dyn_into()?;

    let arrbuf = wasm_bindgen_futures::JsFuture::from(resp.array_buffer()?).await?;
    let arrbuf2 = js_sys::ArrayBuffer::from(arrbuf);
    let u8arr3 = js_sys::Uint8Array::new(&arrbuf2);

    let mut body = vec![0; u8arr3.length() as usize];
    u8arr3.copy_to(&mut body[..]);

    Ok(body)
}

#[wasm_bindgen]
pub async fn query(doh_url: JsValue, name: JsValue, query_type: JsValue) -> Result<JsValue, JsValue> {
    utils::set_panic_hook();

    let doh_url_str = match doh_url.as_string() {
        Some(x) => Ok(x),
        None    => Err("doh_url is not a string."),
    }?;

    let name_str = match name.as_string() {
        Some(x) => Ok(x),
        None    => Err("name is not a string."),
    }?;

    let query_type_str = match query_type.as_string() {
        Some(x) => Ok(x),
        None    => Err("query_type is not a string."),
    }?;

    let query_type_enum = match query_type_str.as_str() {
        "A"     => Ok(trust_dns_proto::rr::RecordType::A),
        "AAAA"  => Ok(trust_dns_proto::rr::RecordType::AAAA),
        "ANY"   => Ok(trust_dns_proto::rr::RecordType::ANY),
        "AXFR"  => Ok(trust_dns_proto::rr::RecordType::AXFR),
        "CAA"   => Ok(trust_dns_proto::rr::RecordType::CAA),
        "CNAME" => Ok(trust_dns_proto::rr::RecordType::CNAME),
        "IXFR"  => Ok(trust_dns_proto::rr::RecordType::IXFR),
        "MX"    => Ok(trust_dns_proto::rr::RecordType::MX),
        "NS"    => Ok(trust_dns_proto::rr::RecordType::NS),
        "NULL"  => Ok(trust_dns_proto::rr::RecordType::NULL),
        "OPT"   => Ok(trust_dns_proto::rr::RecordType::OPT),
        "PTR"   => Ok(trust_dns_proto::rr::RecordType::PTR),
        "SOA"   => Ok(trust_dns_proto::rr::RecordType::SOA),
        "SRV"   => Ok(trust_dns_proto::rr::RecordType::SRV),
        "TLSA"  => Ok(trust_dns_proto::rr::RecordType::TLSA),
        "TXT"   => Ok(trust_dns_proto::rr::RecordType::TXT),
        _       => Err("query_type not recognised."),
    }?;

    // TODO: Implementing From<ProtoError> as a JsValue would be better
    let request_wire_message = match query_as_vec(&name_str, query_type_enum) {
        Ok(x)   => Ok(x),
        Err(_)  => Err("trust_dns_proto::error::ProtoError")
    }?;

    let response_wire_message = wire_with_fetch(&doh_url_str, request_wire_message).await?;

    // TODO: Implementing From<ProtoError> as a JsValue would be better
    let dns_response = match trust_dns_proto::op::Message::from_vec(&response_wire_message) {
        Ok(x)   => Ok(x),
        Err(_)  => Err("trust_dns_proto::error::ProtoError")
    }?;

    let dns_answers = dns_response.answers();

    let result_array = js_sys::Array::new_with_length(dns_answers.len() as u32);

    for (index, answer) in dns_answers.iter().enumerate() {
        result_array.set(index as u32, format!("{:?}", answer).into());
    }

    Ok(result_array.into())
}
