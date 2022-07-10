package corehttp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func Test(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: %x\n", sig)

	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], sig)
	fmt.Println("signature verified:", valid)
}

func TestEn(t *testing.T) {
	// key, _ := hex.DecodeString("03b0fa0d68cf6a4a1ed80bd8242eaf9fec1ef2e1637a85fa438a2bd019e8dacb18")

	// pubKey, _ := crypto.DecompressPubkey(key)

	// publicKeyBytes := crypto.FromECDSAPub(pubKey)

	// addr := crypto.PubkeyToAddress(*pubKey).Hex()
	// fmt.Printf("%#v\n", pubKey)
	// addr := crypto.PubkeyToAddress(*pubKey)
	// fmt.Printf("%#v\n", addr)

	hashsign := crypto.Keccak256Hash([]byte("\x19Ethereum Signed Message:\n3ggg"))
	t.Logf("hashsign: %v\n", hashsign)
	signature, err := hex.DecodeString("3cf7d3deb46b688c384e1d3ee4a5630d761cafb62a0d1ad98c9632cbbad96fdb532c479e7f677b3954eb10d445876a2ef9521ef9563aa896bfd44728185a21741c")
	if err != nil {
		t.Fatalf("error: %v\n", err)
	}
	// t.Logf("pubkey length: %v\n", len(pubKey))
	t.Logf("signature length: %v\n", len(signature))
	// t.Logf("%v\n", signature)
	signature[crypto.RecoveryIDOffset] -= 0x1b
	// t.Logf("%v\n", signature)
	// signature[:len(signature)-1]

	pbk, err := crypto.Ecrecover(hashsign.Bytes(), signature)
	if err != nil {
		t.Fatalf("pbk error: %v\n", err)
	}

	// t.Logf("pbk1: %v\n", key)
	// t.Logf("pbk2: %v\n", pbk)

	// b := crypto.VerifySignature(publicKeyBytes, hashsign.Bytes(), signature[:len(signature)-1])
	// t.Logf("bool: %t\n", b)
	fmt.Println(hexutil.Encode(pbk))
}

func TestGo(t *testing.T) {
	// 0x6643ea30c7136e3d980f3574c47b0e2892a1058d08e100746d211435bb4261e6
	privateKey, err := crypto.HexToECDSA("6643ea30c7136e3d980f3574c47b0e2892a1058d08e100746d211435bb4261e6")
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	fmt.Println(hexutil.Encode(publicKeyBytes))

	data := []byte("\x19Ethereum Signed Message:\n3ggg")
	hash := crypto.Keccak256Hash(data)
	fmt.Println(hash.Hex()) // 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	signature1, err := hexutil.Decode("0x3cf7d3deb46b688c384e1d3ee4a5630d761cafb62a0d1ad98c9632cbbad96fdb532c479e7f677b3954eb10d445876a2ef9521ef9563aa896bfd44728185a217401")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(hexutil.Encode(signature)) // 0x789a80053e4927d0a898db8e065e948f5cf086e32f9ccaa54c1908e22ac430c62621578113ddbb62d509bf6049b8fb544ab06d36f916685a2eb8e57ffadde02301

	sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), signature1)
	if err != nil {
		log.Fatal(err)
	}

	matches := bytes.Equal(sigPublicKey, publicKeyBytes)
	fmt.Println(matches) // true

	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), signature)
	if err != nil {
		log.Fatal(err)
	}

	sigPublicKeyBytes := crypto.FromECDSAPub(sigPublicKeyECDSA)
	matches = bytes.Equal(sigPublicKeyBytes, publicKeyBytes)
	fmt.Println(matches) // true

	signatureNoRecoverID := signature[:len(signature)-1] // remove recovery id
	verified := crypto.VerifySignature(publicKeyBytes, hash.Bytes(), signatureNoRecoverID)
	fmt.Println(verified) // true
}

func TestReversal(t *testing.T) {
	got := reversal([]byte{0xc, 0xb, 0xa})
	want := []byte{0xa, 0xb, 0xc}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expected:%v, got:%v", want, got)
	}
}

func TestJ(t *testing.T) {
	key := "b0fa0d68cf6a4a1ed80bd8242eaf9fec1ef2e1637a85fa438a2bd019e8dacb18"
	msg := `//Convert image to byte
byte[] bytimg = (Byte[])new ImageConverter().ConvertTo(pictureBox1.Image, typeof(Byte[]));  
//Writes to textbox
beforeEnc();
//wrapper for TripleDESCryptoServiceProvider
TripleDESCryptoServiceProvider tripleDES = new TripleDESCryptoServiceProvider();
tripleDES.KeySize = 128;
tripleDES.Key = UTF8Encoding.UTF8.GetBytes(keyBoxTxt.Text);
tripleDES.Mode = CipherMode.ECB;
tripleDES.Padding = PaddingMode.PKCS7;
ICryptoTransform cTransform = tripleDES.CreateEncryptor();
byte[] resultArray = cTransform.TransformFinalBlock(bytimg, 0, bytimg.Length);
tripleDES.Clear();
afterEncTxt.Text = Convert.ToBase64String(resultArray, 0, resultArray.Length);
`
	var ciphermsg string
	if data, err := encodee(key, msg); err == nil {
		ciphermsg = hex.EncodeToString(data)
		t.Logf("ciphertext: %v\n", ciphermsg)
	} else {
		t.Logf("error: %v\n", err)
	}

	if msg, err := decodee(key, ciphermsg); err == nil {
		t.Logf("msg: %v\n", string(msg))
	} else {
		t.Logf("error: %v\n", err)
	}
}
func TestED(t *testing.T) {

	key, _ := hex.DecodeString("b0fa0d68cf6a4a1ed80bd8242eaf9fec1ef2e1637a85fa438a2bd019e8dacb18")
	plaintext := []byte("exampleplaintext")
	block, err := aes.NewCipher(key)

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	fmt.Printf("nonce: %v\n", hexutil.Encode(nonce))
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("ciphertext: %x\n", ciphertext)

	pkey, _ := hex.DecodeString("6643ea30c7136e3d980f3574c47b0e2892a1058d08e100746d211435bb4261e6")
	// pkciphertext, _ := hex.DecodeString("79ac6980bc8b5ef2c2438970f598544f8356771fafb9e12062ed7c2792b09149")
	// nonce, _ := hex.DecodeString(ciphertext[:8])

	pkblock, err := aes.NewCipher(pkey)
	if err != nil {
		panic(err.Error())
	}

	pkaesgcm, err := cipher.NewGCM(pkblock)
	if err != nil {
		panic(err.Error())
	}

	plaintext1, err := pkaesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic("open: " + err.Error())
	}

	fmt.Printf("%s\n", plaintext1)

}

func TestRSA(t *testing.T) {
	// key, _ := hex.DecodeString("b0fa0d68cf6a4a1ed80bd8242eaf9fec1ef2e1637a85fa438a2bd019e8dacb18")
	// plaintext := []byte("exampleplaintext")
	// privateKey, err := crypto.HexToECDSA("6643ea30c7136e3d980f3574c47b0e2892a1058d08e100746d211435bb4261e6")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// publicKey := privateKey.Public()
	// publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey
	t.Logf("prikey: %v\n", privateKey)
	t.Logf("pubkey: %v\n", publicKey)

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		[]byte("super secret message"),
		nil)
	if err != nil {
		panic("encrypte: " + err.Error())
	}

	fmt.Println("encrypted bytes: ", encryptedBytes)

	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: 5})
	if err != nil {
		panic(err)
	}

	fmt.Println("decrypted message: ", string(decryptedBytes))

}

func TestRequest(t *testing.T) {
	client, err := ethclient.Dial("https://zhaogch.com/fications")
	// client, err := ethclient.Dial("/home/unxeer/chain/data/geth.ipc")
	if err != nil {
		t.Errorf("connect ethereum error: %v", err)
		return
	}
	defer client.Close()
	if num, err := client.ChainID(context.TODO()); err == nil {
		t.Logf("%v\n", num.Uint64())
	}

	address := common.HexToAddress("0x3BE8CA26c9949a755683181E9f77293C003A63D5")
	greeter, err := NewGreeter(address, client)
	if err != nil {
		t.Errorf("instance create error: %v\n", err)
		return
	}
	r, err := greeter.Greet(nil)
	if err != nil {
		t.Errorf("request greet() error: %v", err)
		return
	}
	t.Logf("result :%v\n", r)
}
