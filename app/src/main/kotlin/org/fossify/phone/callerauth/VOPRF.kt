package org.fossify.phone.callerauth

import io.github.lokingdav.libdia.LibDia
import org.json.JSONObject

data class Scalar(val encoded: ByteArray)
data class Point(val encoded: ByteArray)
data class BlindedTicket(val input: ByteArray, val blinded: Point, val blind: Scalar)
data class Ticket(val t1: ByteArray, val t2: Point) {
    fun toByteArray(): ByteArray {
        return t1 + t2.encoded
    }

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("t1", Signing.encodeToHex(t1))
            put("t2", Signing.encodeToHex(t2.encoded))
        }
    }

    companion object {
        fun fromJson(data: JSONObject): Ticket {
            return Ticket(
                Signing.decodeHex(data.getString("t1")),
                Point(Signing.decodeHex(data.getString("t2")))
            )
        }
    }
}

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

    fun generateTicket(count: Int): Array<BlindedTicket> {
        return Array(count) {
            val (input, _) = LibDia.voprfKeygen()
            val (blinded, blind) = blind(input)
            BlindedTicket(input, blinded, blind)
        }
    }

    fun finalizeTickets(
        blindedTickets: Array<BlindedTicket>,
        evaluated: Array<Point>
    ): Array<Ticket> {
        return Array(blindedTickets.size) {
            val (input, _, blind) = blindedTickets[it]
            val evalElement = evaluated[it]
            val t2 = finalize(evalElement, blind)
            Ticket(input, t2)
        }
    }

    fun verifyTickets(tickets: Array<Ticket>, verifyKey: ByteArray): Boolean {
        val inputs = tickets.map { it.t1 }.toTypedArray()
        val outputs = tickets.map { it.t2.encoded }.toTypedArray()
        return LibDia.voprfVerifyBatch(inputs, outputs, verifyKey)
    }
}
