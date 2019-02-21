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
import co.rsk.pcc.NativeMethod;
import org.ethereum.core.Block;
import org.ethereum.core.CallTransaction;
import org.ethereum.util.ByteUtil;

import java.math.BigInteger;

/**
 * This implements the "getBitcoinHeader" method
 * that belongs to the BlockHeaderContract native contract.
 *
 * @author Diego Masini
 */
public class GetBitcoinHeader extends NativeMethod {
    private final BlockAccessor blockAccessor;

    private final CallTransaction.Function function = CallTransaction.Function.fromSignature(
            "getBitcoinHeader",
            new String[]{"uint256"},
            new String[]{"bytes"}
    );

    public GetBitcoinHeader(ExecutionEnvironment executionEnvironment, BlockAccessor blockAccessor) {
        super(executionEnvironment);
        this.blockAccessor = blockAccessor;
    }

    @Override
    public CallTransaction.Function getFunction() {
        return function;
    }

    @Override
    public Object execute(Object[] arguments) {
        int blockDepth = ((BigInteger) arguments[0]).intValue();

        Block block = blockAccessor.getBlock(blockDepth, getExecutionEnvironment());
        if (block == null) {
            return ByteUtil.EMPTY_BYTE_ARRAY;
        }

        return block.getBitcoinMergedMiningHeader();
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean onlyAllowsLocalCalls() {
        return false;
    }

    public long getGas(Object[] parsedArguments, byte[] originalData) {
        return 500L + super.getGas(parsedArguments, originalData);
    }
}
