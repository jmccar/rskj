/*
 * This file is part of RskJ
 * Copyright (C) 2017 RSK Labs Ltd.
 * (derived from ethereumJ library, Copyright (c) 2016 <ether.camp>)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package org.ethereum.core.genesis;

import co.rsk.core.Coin;
import co.rsk.core.RskAddress;
import co.rsk.trie.Trie;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.core.AccountState;
import org.ethereum.core.Genesis;
import org.ethereum.crypto.HashUtil;
import org.ethereum.crypto.Keccak256Helper;
import org.ethereum.json.Utils;
import org.ethereum.util.ByteUtil;
import org.ethereum.util.RLP;
import org.ethereum.vm.DataWord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import static org.ethereum.core.AccountState.EMPTY_DATA_HASH;

public class GenesisLoader {

    private static final byte[] EMPTY_LIST_HASH = HashUtil.keccak256(RLP.encodeList());
    private static final Logger logger = LoggerFactory.getLogger("genesisloader");

    public static Genesis loadGenesis(String genesisFile, BigInteger initialNonce, boolean isRsk)  {
        InputStream is = GenesisLoader.class.getResourceAsStream("/genesis/" + genesisFile);
        return loadGenesis(initialNonce, is, isRsk);
    }

    public static Genesis loadGenesis(BigInteger initialNonce, InputStream genesisJsonIS, boolean isRsk)  {
        try {
            GenesisJson genesisJson = new ObjectMapper().readValue(genesisJsonIS, GenesisJson.class);
            Genesis genesis = mapFromJson(initialNonce, genesisJson, isRsk);
            genesis.flushRLP();

            return genesis;
        } catch (Exception e) {
            System.err.println("Genesis block configuration is corrupted or not found ./resources/genesis/...");
            logger.error("Genesis block configuration is corrupted or not found ./resources/genesis/...", e);
            System.exit(-1);
            return null;
        }
    }

    private static Genesis mapFromJson(BigInteger initialNonce, GenesisJson json, boolean rskFormat) {
        byte[] difficulty = Utils.parseData(json.difficulty);
        byte[] coinbase = Utils.parseData(json.coinbase);

        byte[] timestampBytes = Utils.parseData(json.timestamp);
        long timestamp = ByteUtil.byteArrayToLong(timestampBytes);

        byte[] parentHash = Utils.parseData(json.parentHash);
        byte[] extraData = Utils.parseData(json.extraData);

        byte[] gasLimitBytes = Utils.parseData(json.gasLimit);
        long gasLimit = ByteUtil.byteArrayToLong(gasLimitBytes);

        byte[] bitcoinMergedMiningHeader = null;
        byte[] bitcoinMergedMiningMerkleProof = null;
        byte[] bitcoinMergedMiningCoinbaseTransaction = null;
        byte[] minGasPrice = null;

        if (rskFormat) {
            bitcoinMergedMiningHeader = Utils.parseData(json.bitcoinMergedMiningHeader);
            bitcoinMergedMiningMerkleProof = Utils.parseData(json.bitcoinMergedMiningMerkleProof);
            bitcoinMergedMiningCoinbaseTransaction = Utils.parseData(json.bitcoinMergedMiningCoinbaseTransaction);
            minGasPrice = Utils.parseData(json.getMinimumGasPrice());
        }

        Map<RskAddress, AccountState> accounts = new HashMap<>();
        Map<RskAddress, byte[]> codes = new HashMap<>();
        Map<RskAddress, Map<DataWord, byte[]>> storages = new HashMap<>();
        Map<String, AllocatedAccount> alloc = json.getAlloc();
        for (Map.Entry<String, AllocatedAccount> accountEntry : alloc.entrySet()) {
            if(!"00".equals(accountEntry.getKey())) {
                Coin balance = new Coin(new BigInteger(accountEntry.getValue().getBalance()));
                BigInteger accountNonce;

                if (accountEntry.getValue().getNonce() != null) {
                    accountNonce = new BigInteger(accountEntry.getValue().getNonce());
                } else {
                    accountNonce = initialNonce;
                }

                AccountState acctState = new AccountState(accountNonce, balance);
                Contract contract = accountEntry.getValue().getContract();

                RskAddress address = new RskAddress(accountEntry.getKey());
                if (contract != null) {
                    byte[] code = Hex.decode(contract.getCode());
                    codes.put(address, code);
                    acctState.setCodeHash(code == null ? EMPTY_DATA_HASH : Keccak256Helper.keccak256(code));
                    Map<DataWord, byte[]> storage = new HashMap<>(contract.getData().size());
                    for (Map.Entry<String, String> storageData : contract.getData().entrySet()) {
                        storage.put(new DataWord(Hex.decode(storageData.getKey())), Hex.decode(storageData.getValue()));
                    }
                    storages.put(address, storage);
                    acctState.setStateRoot(calculateStateRoot(storage));
                }
                accounts.put(address, acctState);
            }
        }

        return new Genesis(parentHash, EMPTY_LIST_HASH, coinbase, Genesis.getZeroHash(),
                difficulty, 0, gasLimit, 0, timestamp, extraData,
                bitcoinMergedMiningHeader, bitcoinMergedMiningMerkleProof,
                bitcoinMergedMiningCoinbaseTransaction, minGasPrice, accounts, codes, storages);
    }

    private static byte[] calculateStateRoot(Map<DataWord, byte[]> contractStorage) {
        Trie trie = new Trie(true);
        for (Map.Entry<DataWord, byte[]> storageEntry : contractStorage.entrySet()) {
            trie = trie.put(storageEntry.getKey().getData(), storageEntry.getValue());
        }
        return trie.getHash().getBytes();
    }

}
