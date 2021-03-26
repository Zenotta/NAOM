//! App using NAOM library.
#![allow(dead_code)]

use naom::db::display::list_assets;

mod db;

fn main() {
    list_assets();
}
