// functions to verify the startup arguments as correct

use std::net::{SocketAddr, ToSocketAddrs};

pub(crate) fn verify_sock_addr(arg_val: String) -> Result<(), String> {
    match arg_val.parse::<SocketAddr>() {
        Ok(_addr) => Ok(()),
        Err(_) => Err(format!(
            "Could not parse \"{}\" as a valid socket address (with port).",
            arg_val
        )),
    }
}

pub(crate) fn verify_remote_server(arg_val: String) -> Result<(), String> {
    match arg_val.to_socket_addrs() {
        Ok(mut addr_iter) => match addr_iter.next() {
            Some(_) => Ok(()),
            None => Err(format!(
                "Could not parse \"{}\" as a valid remote uri",
                arg_val
            )),
        },
        Err(err) => Err(format!("{}", err)),
    }
}
