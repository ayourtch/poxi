#![recursion_limit = "128"]

// https://cprimozic.net/blog/writing-a-hashmap-to-struct-procedural-macro-in-rust/

extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

// use proc_macro::TokenStream;
use syn::Ident; // , VariantData};
use syn::{
    parse_macro_input, parse_quote, Data, DeriveInput, Fields, GenericParam, Generics, Index, Path,
    Type,
};

struct StructField {
    name: Ident,
    conv: Ident,
}

use proc_macro2::{Punct, Spacing, Span, TokenTree};
use quote::{ToTokens, TokenStreamExt};

impl ToTokens for StructField {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = self.name.clone();
        let conv = self.conv.clone();
        let tk = quote! {
                     match hm.entry(String::from(stringify!(#name))) {
                         ::std::collections::hash_map::Entry::Occupied(occ_ent) => {
                             // set the corresponding struct field to the value in
                             // the corresponding hashmap if it contains it
                             out.#name = #conv(occ_ent.get().as_str());
                         },
                         ::std::collections::hash_map::Entry::Vacant(_) => (),
                     }
        };
        tokens.extend(tk);
    }
}

#[proc_macro_derive(NetworkProtocol)]
pub fn network_protocol(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // let source = input.to_string();
    // Parse the string representation into a syntax tree
    // let ast = syn::parse_macro_input(&source).unwrap();
    //
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let macroname = Ident::new(&format!("{}", &name).to_uppercase(), Span::call_site());
    let varname = Ident::new(&format!("__{}", &name), Span::call_site());

    let mut tokens = quote! {
        impl<T: Layer> Div<T> for #name {
            type Output = LayerStack;
            fn div(mut self, rhs: T) -> Self::Output {
                let mut out = self.to_stack();
                out.layers.push(rhs.embox());
                out
            }
        }
        impl #name {
            pub fn of(stack: &LayerStack) -> Self {
                let res = &stack[TypeId::of::<Self>()];
                res.downcast_ref::<Self>().unwrap().clone()
            }
        }

        impl Layer for #name {
            fn embox(self) -> Box<dyn Layer> {
                Box::new(self)
            }
            fn box_clone(&self) -> Box<dyn Layer> {
                Box::new((*self).clone())
            }
        }


        #[macro_export]
        macro_rules! #macroname {
            () => {{
                {
                    let mut #varname: #name = Default::default();
                    #varname
                }
            }};

            ($ip:ident, $ident:ident=$e:expr) => {{
                {
                    $ip.$ident = TryFrom::try_from($e).unwrap();
                }
            }};
            ($ip: ident, $ident:ident=$e:expr, $($x_ident:ident=$es:expr),+) => {{
                {
                    #macroname!($ip, $ident=$e);
                    #macroname!($ip, $($x_ident=$es),+);
                }
            }};

            ($ident:ident=$e:expr) => {{
                {
                    let mut #varname: #name = Default::default();
                    #macroname!(#varname, $ident=$e);
                    #varname
                }
            }};
            ($ident:ident=$e:expr, $($s_ident:ident=$es:expr),+) => {{
                {
                    let mut #varname = #macroname!($ident=$e);
                    #macroname!(#varname, $($s_ident=$es),+);
                    #varname
                }
            }};

        }


    };
    eprintln!("{}", tokens.to_string());

    proc_macro::TokenStream::from(tokens)
}




#[proc_macro_derive(FromStringHashmap)]
pub fn from_string_hashmap(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
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
    let generics = add_trait_bounds(input.generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut tokens = quote! {
        impl #impl_generics FromStringHashmap<#name> for #name #ty_generics #where_clause {
            fn from_string_hashmap(mut hm: ::std::collections::HashMap<String, String>) -> #name {
                // start with the default implementation
                let mut out = #name::default();
                #(
                    #idents;
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
fn struct_fields(data: &Data) -> Vec<StructField> {
    fn path_is_option(path: &Path) -> bool {
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments.iter().next().unwrap().ident == "Option"
    }
    fn path_is_vec(path: &Path) -> bool {
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments.iter().next().unwrap().ident == "Vec"
    }

    let mut out = vec![];

    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    for f in &fields.named {
                        let name = f.ident.clone().unwrap();
                        // panic!("FIELD: {:#?}", f.ty);
                        match &f.ty {
                            Type::Path(typepath)
                                if typepath.qself.is_none() && path_is_option(&typepath.path) =>
                            {
                                out.push(StructField {
                                    name,
                                    conv: format_ident!("parse_pair_as_option"),
                                });
                            }
                            Type::Path(typepath)
                                if typepath.qself.is_none() && path_is_vec(&typepath.path) =>
                            {
                                out.push(StructField {
                                    name,
                                    conv: format_ident!("parse_pair_as_vec"),
                                });
                            }
                            _ => {
                                out.push(StructField {
                                    name,
                                    conv: format_ident!("parse_pair"),
                                });
                            }
                        }
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
                Fields::Unit => {}
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
