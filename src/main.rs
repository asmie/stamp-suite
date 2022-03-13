mod configuration;
mod packets;
mod sender;

use crate::configuration::*;
use configuration::Configuration;


fn main()
{
    let args = Configuration::parse();

    let s = args.count;

    println!("Hello {} {}!", args.remote_addr, s as u8);

}
