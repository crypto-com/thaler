//
//  MyData.swift
//  IosSample

import Foundation
class MyData : Codable {
    var tendermint: String? = "ws://localhost:26657/websocket"
    var name: String? = "a"
    var passphras: String? = ""
    var enckey: String? = ""
    var mnemonics: String? = ""
}
