import * as wasm from "wasm-dns-client";

// wasm.query("www.google.com.", "A");
let input = document.getElementById("domain-input");
let output = document.getElementById("output-area");
let button = document.getElementById("query-button");
let query_type = document.getElementById("query-type");

let run_query = ev => {
  wasm.query("https://doh.magellanic.dev/dns-query", input.value, query_type.value).then(result => {
    output.value = JSON.stringify(result, null, 2);
  });
};

let run_query_if_enter = ev => {
  if (ev.key === "Enter") {
    run_query(ev);
    ev.preventDefault();
    return false;
  }
};

input.addEventListener("keyup", run_query_if_enter);
button.addEventListener("click", run_query);
