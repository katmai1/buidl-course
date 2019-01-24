from uuid import uuid4


#
class TxIn:
    def __init__(self, tx_id, index, signature):
        self.tx_id = tx_id
        self.index = index
        self.signature = signature

    def spend_message(self):
        return f"{self.tx_id}:{self.index}".encode()

    @property
    def outpoint(self):
        return (self.tx_id, self.index)


#
class TxOut:
    def __init__(self, tx_id, index, amount, public_key):
        self.tx_id = tx_id
        self.index = index
        self.amount = amount
        self.public_key = public_key

    @property
    def outpoint(self):
        return (self.tx_id, self.index)

#
class Tx:
    def __init__(self, id, tx_ins, tx_outs):
        self.id = id
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs

    def sign_input(self, index, private_key):
        spend_message = self.tx_ins[index].spend_message()
        signature = private_key.sign(spend_message)
        self.tx_ins[index].signature = signature
    
#
class Bank:
    def __init__(self):
        self.utxo = {}

    def update_utxo(self, tx):
        for tx_in in tx.tx_ins:
            del self.utxo[tx_in.outpoint]
        for tx_out in tx.tx_outs:
            self.utxo[tx_out.outpoint] = tx_out

    def issue(self, amount, public_key):
        id = uuid4()
        tx_ins = []
        tx_outs = [
            TxOut(tx_id=id, index=0, amount=amount, public_key=public_key),
        ]
        # creamos transaccion y la añadimos al diccionario
        tx = Tx(id=id, tx_ins=tx_ins, tx_outs=tx_outs)
        self.update_utxo(tx)
        return tx

    def fetch_utxo(self, public_key):
        return [utxo for utxo in self.utxo.values()
            if utxo.public_key.to_string() == public_key.to_string()]

    def fetch_balance(self, public_key):
        utxo = self.fetch_utxo(public_key)
        return sum([tx_out.amount for tx_out in utxo])

    def validate_tx(self, tx):
        in_sum = 0
        out_sum = 0
        for tx_in in tx.tx_ins:
            assert tx_in.outpoint in self.utxo
            tx_out = self.utxo[tx_in.outpoint]
            public_key = tx_out.public_key
            public_key.verify(tx_in.signature, tx_in.spend_message())
            in_sum += tx_out.amount
        for tx_out in tx.tx_outs:
            out_sum += tx_out.amount
        assert in_sum == out_sum

    def handle_tx(self, tx):
        self.validate_tx(tx)
        self.update_utxo(tx)