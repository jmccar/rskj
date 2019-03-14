/*
 * This file is part of RskJ
 * Copyright (C) 2017 RSK Labs Ltd.
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

package co.rsk.trie;

import co.rsk.crypto.Keccak256;
import org.ethereum.crypto.HashUtil;
import org.ethereum.util.RLP;
import org.junit.Assert;
import org.junit.Test;

import static org.ethereum.util.ByteUtil.EMPTY_BYTE_ARRAY;

/**
 * Created by ajlopez on 03/04/2017.
 */
public class SecureTrieHashTest {
    private static Keccak256 emptyHash = makeEmptyHash();

    @Test
    public void getNotNullHashOnEmptyTrie() {
        Trie trie = new Trie(true);

        Assert.assertNotNull(trie.getHash().getBytes());
    }

    @Test
    public void getHashAs32BytesOnEmptyTrie() {
        Trie trie = new Trie(true);

        Assert.assertEquals(32, trie.getHash().getBytes().length);
    }

    @Test
    public void emptyTriesHasTheSameHash() {
        Trie trie1 = new Trie(true);
        Trie trie2 = new Trie(true);
        Trie trie3 = new Trie(true);

        Assert.assertEquals(trie1.getHash(), trie1.getHash());
        Assert.assertEquals(trie1.getHash(), trie2.getHash());
        Assert.assertEquals(trie3.getHash(), trie2.getHash());
    }

    @Test
    public void emptyHashForEmptyTrie() {
        Trie trie = new Trie(true);

        Assert.assertEquals(emptyHash, trie.getHash());
    }

    @Test
    public void nonEmptyHashForNonEmptyTrie() {
        Trie trie = new Trie(true);

        trie = trie.put("foo".getBytes(), "bar".getBytes());

        Assert.assertNotEquals(emptyHash, trie.getHash());
    }

    @Test
    public void triesWithSameKeyValuesHaveSameHash() {
        Trie trie1 = new Trie(true)
                .put("foo", "bar".getBytes())
                .put("bar", "baz".getBytes());
        Trie trie2 = new Trie(true)
                .put("foo", "bar".getBytes())
                .put("bar", "baz".getBytes());

        Assert.assertEquals(trie1.getHash(), trie2.getHash());
    }

    @Test
    public void triesWithSameKeyLongValuesHaveSameHash() {
        byte[] value1 = TrieValueTest.makeValue(100);
        byte[] value2 = TrieValueTest.makeValue(200);

        Trie trie1 = new Trie(true)
                .put("foo", value1)
                .put("bar", value2);
        Trie trie2 = new Trie(true)
                .put("foo", value1)
                .put("bar", value2);

        Assert.assertEquals(trie1.getHash(), trie2.getHash());
    }

    @Test
    public void triesWithSameKeyValuesInsertedInDifferentOrderHaveSameHash() {
        Trie trie1 = new Trie(true)
                .put("foo", "bar".getBytes())
                .put("bar", "baz".getBytes());
        Trie trie2 = new Trie(true)
                .put("bar", "baz".getBytes())
                .put("foo", "bar".getBytes());

        Assert.assertEquals(trie1.getHash(), trie2.getHash());
    }

    @Test
    public void triesWithSameKeyLongValuesInsertedInDifferentOrderHaveSameHash() {
        byte[] value1 = TrieValueTest.makeValue(100);
        byte[] value2 = TrieValueTest.makeValue(200);

        Trie trie1 = new Trie(true)
                .put("foo", value1)
                .put("bar", value2);
        Trie trie2 = new Trie(true)
                .put("bar", value2)
                .put("foo", value1);

        Assert.assertEquals(trie1.getHash(), trie2.getHash());
    }

    @Test
    public void threeTriesWithSameKeyValuesInsertedInDifferentOrderHaveSameHash() {
        Trie trie1 = new Trie(true)
                .put("foo".getBytes(), "bar".getBytes())
                .put("bar".getBytes(), "baz".getBytes())
                .put("baz".getBytes(), "foo".getBytes());
        Trie trie2 = new Trie(true)
                .put("bar".getBytes(), "baz".getBytes())
                .put("baz".getBytes(), "foo".getBytes())
                .put("foo".getBytes(), "bar".getBytes());
        Trie trie3 = new Trie(true)
                .put("baz".getBytes(), "foo".getBytes())
                .put("bar".getBytes(), "baz".getBytes())
                .put("foo".getBytes(), "bar".getBytes());

        Assert.assertEquals(trie1.getHash(), trie2.getHash());
        Assert.assertEquals(trie3.getHash(), trie2.getHash());
    }

    @Test
    public void threeTriesWithSameKeyLongValuesInsertedInDifferentOrderHaveSameHash() {
        byte[] value1 = TrieValueTest.makeValue(100);
        byte[] value2 = TrieValueTest.makeValue(150);
        byte[] value3 = TrieValueTest.makeValue(200);

        Trie trie1 = new Trie(true)
                .put("foo".getBytes(), value1)
                .put("bar".getBytes(), value2)
                .put("baz".getBytes(), value3);
        Trie trie2 = new Trie(true)
                .put("bar".getBytes(), value2)
                .put("baz".getBytes(), value3)
                .put("foo".getBytes(), value1);
        Trie trie3 = new Trie(true)
                .put("baz".getBytes(), value3)
                .put("bar".getBytes(), value2)
                .put("foo".getBytes(), value1);

        Assert.assertEquals(trie1.getHash(), trie2.getHash());
        Assert.assertEquals(trie3.getHash(), trie2.getHash());
    }

    @Test
    public void triesWithDifferentKeyValuesHaveDifferentHashes() {
        Trie trie1 = new Trie(true)
                .put("foo", "bar".getBytes())
                .put("bar", "42".getBytes());
        Trie trie2 = new Trie(true)
                .put("foo", "bar".getBytes())
                .put("bar", "baz".getBytes());

        Assert.assertNotEquals(trie1.getHash(), trie2.getHash());
    }

    @Test
    public void triesWithDifferentKeyLongValuesHaveDifferentHashes() {
        Trie trie1 = new Trie(true)
                .put("foo", TrieValueTest.makeValue(100))
                .put("bar", TrieValueTest.makeValue(110));
        Trie trie2 = new Trie(true)
                .put("foo", TrieValueTest.makeValue(120))
                .put("bar", TrieValueTest.makeValue(130));

        Assert.assertNotEquals(trie1.getHash(), trie2.getHash());
    }

    public static Keccak256 makeEmptyHash() {
        return new Keccak256(HashUtil.keccak256(RLP.encodeElement(EMPTY_BYTE_ARRAY)));
    }
}
