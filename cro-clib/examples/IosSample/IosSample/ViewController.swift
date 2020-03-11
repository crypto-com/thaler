//  ViewController.swift
//  IosSample


import UIKit

class ViewController: UIViewController {
    var my_data: MyData = MyData()
    var file_url: URL?
    var my_filename = "info1.json"
    var my_storage = "storage"
    var doing_sync:Bool = false
    @IBOutlet weak var wallet_tendermint_url: UITextField!
    @IBOutlet weak var wallet_name: UITextField!
    @IBOutlet weak var wallet_passphrase: UITextField!
    @IBOutlet weak var wallet_enckey: UITextField!
    @IBOutlet weak var wallet_mnemonics: UITextField!
    @IBOutlet weak var wallet_progress: UIProgressView!
    func save() throws {
        let jsonEncoder = JSONEncoder()
        let jsonData = try jsonEncoder.encode(my_data)
        let jsonString = String(data: jsonData, encoding: String.Encoding.utf8)!
        try jsonString.write(to: file_url!, atomically: true, encoding: String.Encoding.utf8)
        let userData = my_data
        print("save \(userData.name!) \(userData.mnemonics!)")
    }
    func load() throws {
        let jsonText = try String(contentsOf: file_url!, encoding: .utf8)
        let jsonData = jsonText.data(using: .utf8)!
        let jsonDecoder = JSONDecoder()
        let userData = try jsonDecoder.decode(MyData.self, from: jsonData)
        my_data=userData
        print("load \(userData.name!) \(userData.mnemonics!)")
    }
    override func viewDidLoad() {
        super.viewDidLoad()
        do {
            file_url=getDocumentsDirectoryURL().appendingPathComponent(my_filename)
            try load()
            wallet_tendermint_url.text = my_data.tendermint
            wallet_name.text = my_data.name
            wallet_passphrase.text = my_data.passphras
            wallet_enckey.text = my_data.enckey
            wallet_mnemonics.text = my_data.mnemonics
        }
        catch {
            print("view load error")
        }
    }
    
    func getDocumentsDirectoryURL() -> URL {
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        let documentsDirectory = paths[0]
        return documentsDirectory
    }
    
    @IBAction func click_create_wallet(_ sender: Any) {
        let name = wallet_name.text!
        let passphrase = wallet_passphrase.text!
        let mnemonics = wallet_mnemonics.text!
        let enckey = wallet_enckey.text!
        let storage = getDocumentsDirectoryURL().appendingPathComponent(my_storage).path
        print("storage \(storage)")
        print("click wallet = \(name)  passphrase=\(passphrase) mnemonics=\(mnemonics	)")
        my_data.tendermint = wallet_tendermint_url.text
        my_data.name = name
        my_data.passphras = passphrase
        my_data.enckey = enckey
        my_data.mnemonics = mnemonics
        do {
            try save()
        }
        catch {
            print("save error")
        }
        restore_wallet(wallet_tendermint_url.text, storage, name, passphrase, enckey, mnemonics)
    }
    
    @IBAction func click_create_sync(_ sender: Any) {
        if doing_sync {
            stop_sync()
            return
        }
        print("click sync")
        let tendermint = wallet_tendermint_url.text
        let name = wallet_name.text!
        let passphrase = wallet_passphrase.text!
        let mnemonics = wallet_mnemonics.text!
        let enckey = wallet_enckey.text!
        let storage = getDocumentsDirectoryURL().appendingPathComponent(my_storage).path
        print("storage \(storage)")
        print("click wallet = \(name)  passphrase=\(passphrase) mnemonics=\(mnemonics    )")
        my_data.tendermint = wallet_tendermint_url.text
        my_data.name = name
        my_data.passphras = passphrase
        my_data.enckey = enckey
        my_data.mnemonics = mnemonics
        doing_sync = true
        DispatchQueue.global(qos: .background).async {
            sync_wallet(tendermint, storage, name, passphrase, enckey, mnemonics)
            DispatchQueue.main.async {
                self.doing_sync = false
            }
        }
        DispatchQueue.global(qos: .background).async {
            while (self.doing_sync) {
                usleep(50000);// 50 milli-sec
                DispatchQueue.main.async {
                    self.wallet_progress.progress = get_rate()
                }
            }
        }
    }
    @IBAction func click_default(_ sender: Any) {
        do {
            print("click default")
            wallet_tendermint_url.text = "ws://localhost:26657/websocket"
            wallet_name.text = "a"
            wallet_passphrase.text = ""
            wallet_enckey.text = ""
            wallet_mnemonics.text = ""
            try save()
        }
        catch {
            print("click default error")
        }
    }
}

