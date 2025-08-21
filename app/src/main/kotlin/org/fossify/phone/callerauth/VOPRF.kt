package org.fossify.phone.callerauth

import io.github.lokingdav.libdia.LibDia

data class Scalar(val encoded: ByteArray)
data class Point(val encoded: ByteArray)

object VOPRF {
    fun blind(input: ByteArray): Pair<Point, Scalar> {
        val res = LibDia.voprfBlind(input)
        return Pair(
            Point(res[0]),
            Scalar(res[1])
        )
    }

    fun finalize(evalElement: Point, scalar: Scalar): Point {
        val bytes = LibDia.voprfUnblind(evalElement.encoded, scalar.encoded)
        return Point(bytes)
    }
}
