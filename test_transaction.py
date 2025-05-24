from transaction import Transaction, generate_keys

def main():
    priv_key, pub_key = generate_keys()

    # Создаем транзакцию
    tx_inputs = [{'tx_id': 'prev_tx_hash_1', 'output_index': 0}]
    tx_outputs = [{'address': 'user_B', 'amount': 100.0}]
    tx = Transaction(tx_inputs, tx_outputs)

    print("До подписи:", tx.to_json())
    tx.sign(priv_key)
    print("После подписи:", tx.to_json(include_signature=True))

    valid = tx.verify_signature(pub_key)
    print("Подпись действительна?", valid)

if __name__ == "__main__":
    main()
