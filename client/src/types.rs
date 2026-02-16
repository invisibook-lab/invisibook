
#[derive()]
pub struct OrderAmount(pub u64);

impl OrderAmount {
    pub fn new() -> OrderAmount {
        OrderAmount(0)
    }
}