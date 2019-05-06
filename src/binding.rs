pub mod java {
    use crate::IronOxideErr;
    /// A way to turn IronSdkErr into Strings for the Java binding
    impl From<IronOxideErr> for String {
        fn from(err: IronOxideErr) -> Self {
            format!("{}", err)
        }
    }
}
