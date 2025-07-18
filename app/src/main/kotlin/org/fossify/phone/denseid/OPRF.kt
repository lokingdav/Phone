package org.fossify.phone.denseid

import io.github.denseidentity.bbsgroupsig.BBSGS

data class Scalar(val encoded: ByteArray)
data class Point(val encoded: ByteArray)

object OPRF {
    fun blind(input: ByteArray): Pair<Point, Scalar> {
        val scalar = BBSGS.ecScalarRandom()
        val point = BBSGS.ecG1HashToPoint(input)
        val blindedEl = BBSGS.ecG1Mul(point, scalar)
        return Pair(Point(blindedEl), Scalar(scalar))
    }

    fun finalize(evalElement: Point, scalar: Scalar): Point {
        val scalarInv = BBSGS.ecScalarInverse(scalar.encoded)
        val finalEl = BBSGS.ecG1Mul(evalElement.encoded, scalarInv)
        return Point(finalEl)
    }
}
