# Notarised Append Only Memory (NAOM)

Die NAOM repo bevat al die nodige kode om 'n plaaslike instansie van die Zenotta blockchain op te stel en te kommunikeer. 
Ander taalopsies kan hier gevind word:

- [English](https://gitlab.com/zenotta/naom/-/blob/main/README.md)
- [中文](https://gitlab.com/zenotta/naom/-/blob/main/README.zhs.md)
- [Deutsch](https://gitlab.com/zenotta/naom/-/blob/main/README.de.md)
- [Française](https://gitlab.com/zenotta/naom/-/blob/main/README.fr.md)

As jy met vertalings wil help, of as jy 'n fout sien, open dan gerus 'n nuwe merge request.

..

## Ontwikkeling

Vir ontwikkeling benodig NAOM die volgende installasies:

- [Rust](https://www.rust-lang.org/tools/install)

Jy kan hierdie repo kloon en die toetse so uitvoer:

```
cargo build
cargo test
```

Voordat jy enige kode na hierdie repo stuur, word aanbeveel dat jy `make` gebruik om die kode te formaat en vir die CI te pluis.

..

## Gebruik

As jy `cargo run --bin main` uitvoer, word tans alle bates in die plaaslike instansie gelys. NAOM is gewoonlik nie bedoel om direk te gebruik nie, en is eerder bedoel om gebruik te word van ander programme wat toegang tot die blockchain-datastruktuur benodig.