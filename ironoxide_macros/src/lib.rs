extern crate proc_macro;
use proc_macro::TokenStream;
use syn::{parse, parse::Parser, token::Async, Attribute, Item, ItemTrait, TraitItem};

#[proc_macro_attribute]
pub fn add_async(attr: TokenStream, input: TokenStream) -> TokenStream {
    let is_async: String = attr.to_string();
    match &is_async[..] {
        "blocking" => input,
        "async" => {
            let item: Item = parse(input).expect("failed to parse input");
            let item_trait = match item {
                Item::Trait(outer_trait) => outer_trait,
                _ => panic!(),
            };
            let trait_items = item_trait
                .items
                .into_iter()
                .map(|trait_item| match trait_item {
                    TraitItem::Method(mut method) => {
                        let new_async = Async {
                            span: proc_macro2::Span::call_site(),
                        };
                        method.sig.asyncness = Some(new_async);
                        TraitItem::Method(method)
                    }
                    _ => panic!(),
                })
                .collect::<Vec<_>>();
            let tokens: TokenStream = "#[async_trait]".parse().unwrap();
            let parser = Attribute::parse_outer;
            let new_attrs = parser.parse(tokens).unwrap();
            let new_item_trait = ItemTrait {
                attrs: new_attrs,
                vis: item_trait.vis,
                unsafety: item_trait.unsafety,
                auto_token: item_trait.auto_token,
                trait_token: item_trait.trait_token,
                ident: item_trait.ident,
                generics: item_trait.generics,
                colon_token: item_trait.colon_token,
                supertraits: item_trait.supertraits,
                brace_token: item_trait.brace_token,
                items: trait_items,
            };
            let output = proc_quote::quote! { #new_item_trait };
            output.into()
        }
        _ => panic!(),
    }
}
