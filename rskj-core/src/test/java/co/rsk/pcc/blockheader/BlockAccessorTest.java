/*
 * This file is part of RskJ
 * Copyright (C) 2019 RSK Labs Ltd.
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

package co.rsk.pcc.blockheader;

import co.rsk.pcc.ExecutionEnvironment;
import co.rsk.pcc.NativeContractIllegalArgumentException;
import org.ethereum.core.Block;
import org.ethereum.db.BlockStore;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.mockito.Mockito.mock;

public class BlockAccessorTest {
    private BlockStore blockStore;
    private BlockAccessor blockAccessor;
    private ExecutionEnvironment executionEnvironment;

    @Before
    public void createBlockAccessor() {
        blockAccessor = new BlockAccessor(100);
    }

    @Test
    public void getBlockBeyondMaximumBlockDepth() {
        executionEnvironment = mock(ExecutionEnvironment.class);

        Assert.assertNull(blockAccessor.getBlock(100, executionEnvironment));
        Assert.assertNull(blockAccessor.getBlock(101, executionEnvironment));
    }

    @Test(expected = NativeContractIllegalArgumentException.class)
    public void getBlockWithNegativeDepth() {
        executionEnvironment = mock(ExecutionEnvironment.class);

        blockAccessor.getBlock(-1, executionEnvironment);
    }

    @Test
    public void getGenesisBlock() {
        ExecutionEnvironment executionEnvironment = EnvironmentUtils.getEnvironmentWithBlockchainOfLength(1);

        Block genesis = blockAccessor.getBlock(0, executionEnvironment);
        Block firstBlock = blockAccessor.getBlock(1, executionEnvironment);

        Assert.assertEquals(0, genesis.getNumber());
        Assert.assertNull(firstBlock);
    }

    @Test
    public void getTenBlocksFromTheTip() {
        ExecutionEnvironment executionEnvironment = EnvironmentUtils.getEnvironmentWithBlockchainOfLength(100);

        for(int i = 0; i < 10; i++) {
            Block block = blockAccessor.getBlock(i, executionEnvironment);
            Assert.assertEquals(99 - i, block.getNumber());
        }
    }
}
