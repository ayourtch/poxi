#![recursion_limit = "128"]

// https://cprimozic.net/blog/writing-a-hashmap-to-struct-procedural-macro-in-rust/

extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;
use syn::Ident; // , VariantData};
use syn::{parse_macro_input, parse_quote, Data, DeriveInput, Fields, GenericParam, Generics, Index};

#[proc_macro_derive(FromStringHashmap)]
pub fn from_string_hashmap(input: TokenStream) -> TokenStream {
    // let source = input.to_string();
    // Parse the string representation into a syntax tree
    // let ast = syn::parse_macro_input(&source).unwrap();
    //
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = input.ident;


    // create a vector containing the names of all fields on the struct
    let idents = struct_fields(&input.data);

    // contains quoted strings containing the struct fields in the same order as
    // the vector of idents.
    //
    let mut keys = Vec::new();
    let mut parsers = Vec::new();
    for (ident, ident_parser) in idents.iter() {
        keys.push(ident.clone());
        parsers.push(ident_parser);
    }

    let generics = add_trait_bounds(input.generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let tokens = quote! {
        impl #impl_generics FromStringHashmap<#name> for #name #ty_generics #where_clause {
            fn from_string_hashmap(mut hm: ::std::collections::HashMap<String, String>) -> #name {
                // start with the default implementation
                let mut out = #name::default();
                #(
                    match hm.entry(String::from(stringify!(#keys))) {
                        ::std::collections::hash_map::Entry::Occupied(occ_ent) => {
                            // set the corresponding struct field to the value in
                            // the corresponding hashmap if it contains it
                            out.#keys = #parsers(occ_ent.get().as_str());
                        },
                        ::std::collections::hash_map::Entry::Vacant(_) => (),
                    }
                )*

                // return the modified struct
                out
            }
        }
    };


    proc_macro::TokenStream::from(tokens)
}

// Add a bound `T: HeapSize` to every type parameter T.
fn add_trait_bounds(mut generics: Generics) -> Generics {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            // type_param.bounds.push(parse_quote!(heapsize::HeapSize));
        }
    }
    generics
}


// Generate an expression to sum up the heap size of each field.
fn struct_fields(data: &Data) -> Vec<(Ident, Ident)> {

    let mut out = vec![];

    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    for f in &fields.named {
                        let name = f.ident.clone().unwrap();
                        //panic!("FIELD: {:#?}", f);
                        out.push((name, format_ident!("parse_pair")));
                    }
                }
                Fields::Unnamed(ref fields) => {
                    // Expands to an expression like
                    //
                    //     0 + self.0.heap_size() + self.1.heap_size() + self.2.heap_size()
                    /*
                    let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                        let index = Index::from(i);
                        quote_spanned! {f.span()=>
                            heapsize::HeapSize::heap_size_of_children(&self.#index)
                        }
                    });
                    */
                }
                Fields::Unit => {
                }
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
    out
}


#[test]
fn test_fancy_repetition() {
    let foo = vec!["a", "b"];
    let bar = vec![true, false];

    let tokens = quote! {
        #(#foo: #bar),*
    };

    let expected = r#""a" : true , "b" : false"#;
    assert_eq!(expected, tokens.as_str());
}
