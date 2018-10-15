use ekiden_core::error::{Error, Result};
use ekiden_trusted::db::database_schema;

database_schema! {
    pub struct TokenDb {
        pub name: String,
        pub symbol: String,
        pub total_supply: u64,
        pub balance_of: Map<String, u64>,
    }
}

pub struct TokenContract {
    /// Token database.
    db: TokenDb,
}

impl TokenContract {
    pub fn new() -> Self {
        TokenContract { db: TokenDb::new() }
    }

    pub fn create(
        &self,
        sender: String,
        name: String,
        symbol: String,
        initial_supply: u64,
    ) -> Result<()> {
        // TODO: Ensure that the contract has not yet been initialized.

        let decimals = 18;
        let total_supply = initial_supply * 10u64.pow(decimals);

        // Initialize contract, overwriting any previous state.
        self.db.name.insert(&name);
        self.db.symbol.insert(&symbol);
        self.db.total_supply.insert(&total_supply);
        self.db.balance_of.insert(&sender, &total_supply);

        Ok(())
    }

    fn get_from_balance(&self, addr: &String, value: u64) -> Result<u64> {
        match self.db.balance_of.get(addr) {
            None => Err(Error::new("Nonexistent `from` account")),
            Some(b) if b < value => Err(Error::new("Insufficient `from` balance")),
            Some(b) => Ok(b),
        }
    }

    fn get_to_balance(&self, addr: &String) -> Result<u64> {
        match self.db.balance_of.get(addr) {
            Some(b) => Ok(b),
            None => Ok(0),
        }
    }

    fn do_transfer(&self, from: String, to: String, value: u64) -> Result<()> {
        let from_balance = self.get_from_balance(&from, value)?;
        let to_balance = self.get_to_balance(&to)?;
        if to_balance + value <= to_balance {
            return Err(Error::new(
                "Transfer value too large, overflow `to` account",
            ));
        }

        // Set new balances.
        let previous_balances = from_balance + to_balance;
        let from_balance = from_balance - value;
        let to_balance = to_balance + value;
        self.db.balance_of.insert(&from, &from_balance);
        self.db.balance_of.insert(&to, &to_balance);

        Ok(())
    }

    // PUBLIC METHODS
    // - callable over RPC
    pub fn get_name(&self) -> Result<String> {
        match self.db.name.get() {
            Some(name) => Ok(name),
            None => Err(Error::new("Contract not yet initialized")),
        }
    }

    pub fn get_symbol(&self) -> Result<String> {
        match self.db.symbol.get() {
            Some(symbol) => Ok(symbol),
            None => Err(Error::new("Contract not yet initialized")),
        }
    }

    pub fn get_balance(&self, msg_sender: &String) -> Result<u64> {
        self.get_to_balance(msg_sender)
    }

    pub fn transfer(&self, msg_sender: String, to: String, value: u64) -> Result<()> {
        self.do_transfer(msg_sender, to, value)
    }

    pub fn burn(&self, msg_sender: String, value: u64) -> Result<()> {
        let total_supply = match self.db.total_supply.get() {
            Some(supply) => supply,
            None => return Err(Error::new("Contract not yet initialized")),
        };

        let from_balance = self.get_from_balance(&msg_sender, value)?;
        self.db
            .balance_of
            .insert(&msg_sender, &(from_balance - value));
        self.db.total_supply.insert(&(total_supply - value));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract() {
        let name = "Ekiden Token";
        let symbol = "EKI";
        let a1 = "testaddr";

        let contract = TokenContract::new();
        contract.create(
            "testaddr".to_owned(),
            "Ekiden Token".to_owned(),
            "EKI".to_owned(),
            8,
        );

        assert_eq!(name, contract.get_name().unwrap(), "name should be set");
        assert_eq!(
            symbol,
            contract.get_symbol().unwrap(),
            "symbol should be set"
        );

        assert_eq!(
            contract.get_balance(&"testaddr".to_owned()).unwrap(),
            8_000_000_000_000_000_000,
            "creator should get all the tokens"
        );
    }
}
