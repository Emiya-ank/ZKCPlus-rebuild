package main

import (
	offchain "Off-ChainAgent/src"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	fmt.Println("测试功能···")

	testpath := "./data/data.txt"
	testpath2 := "./data/encrypted_data.bin"
	publicInputspath := "./data/publicInputs.json"
	pkpath := "./data/pk.bin"
	vkpath := "./data/vk.bin"
	proofpath := "./data/proof.bin"
	// keyHashpath := "data/keyHash.json"
	witnesspath := "./data/witness.json"

	fmt.Println("1. 测试 readPlaintext 函数···")
	plaintext, textLen, err := offchain.ReadPlaintext(testpath, 1024)
	if err != nil {
		panic(fmt.Sprintf("readPlaintext 函数测试失败：%v", err))
	}
	fmt.Printf("明文读取成功：实际长度 = %d, 数组长度 = %d\n", textLen, len(plaintext))

	fmt.Println("2. 测试 roundConstantGeneration 函数···")
	rc := offchain.RoundConstantGeneration()
	if len(rc) != offchain.ROUNDS {
		panic(fmt.Sprintf("轮常量生成错误：期望长度：%d, 实际长度：%d\n", offchain.ROUNDS, len(rc)))
	}
	fmt.Printf("%d 个轮常量生成成功\n", len(rc))

	fmt.Println("3. 测试 keystreamGeneration 函数···")

	key := big.NewInt(19)
	nonce := big.NewInt(9)

	keystream := offchain.KeystreamGeneration(key, nonce, len(plaintext))
	if len(keystream) != len(plaintext) {
		panic(fmt.Sprintf("密钥流长度错误：期望长度：%d, 实际长度：%d\n", len(plaintext), len(keystream)))
	}
	fmt.Printf("基于密钥k = %d, 长度为 %d 的密钥流生成成功\n", key, len(keystream))

	fmt.Println("4. 测试 mimcEncryption 函数···")
	ciphertext := offchain.MimcEncryption(plaintext, key, nonce, textLen)
	if len(ciphertext) != len(plaintext) {
		panic(fmt.Sprintf("密文长度错误：期望长度：%d, 实际长度：%d", len(plaintext), len(ciphertext)))
	}
	fmt.Printf("加密成功：明文长度：%d, 密文长度：%d\n", len(plaintext), len(ciphertext))

	fmt.Println("5. 测试 mimcDecryption 函数···")
	decryptedtext := offchain.MimcDecryption(ciphertext, key, nonce, textLen)
	allmatch := true
	for i := 0; i < len(plaintext); i++ {
		modulus := fr.Modulus()
		expected := new(big.Int).Mod(plaintext[i], modulus)
		actual := new(big.Int).Mod(decryptedtext[i], modulus)

		if expected.Cmp(actual) != 0 {
			allmatch = false
			fmt.Printf("   第 %d 个元素不匹配: 期望 %v, 实际 %v\n", i, expected, actual)
		}
	}
	if !allmatch {
		panic("解密失败: 解密结果与原文不匹配")
	}
	fmt.Println("解密成功: 解密结果与原文匹配")

	fmt.Println("6. 测试 writeCiphertext 函数···")
	err = offchain.WriteText(testpath2, ciphertext)
	if err != nil {
		panic("密文写入失败!")
	}
	fmt.Println("密文写入成功!")

	fmt.Println("7. 测试 readCiphertext 函数···")
	ciphertext, err = offchain.ReadCiphertext(testpath2)
	if err != nil {
		panic("密文读取失败!")
	}
	fmt.Println("密文读取成功!")

	fmt.Println("8. 测试导出 publicInputs.json···")
	selector := make([]*big.Int, offchain.MAX_N)
	for i := 0; i < offchain.MAX_N; i++ {

		if i < textLen {
			selector[i] = big.NewInt(1)
		} else {
			selector[i] = big.NewInt(0)
		}
	}
	err = offchain.ExportPublicJSON(ciphertext, selector, textLen, publicInputspath)
	if err != nil {
		panic("publicInputs.json 生成失败！")
	}
	fmt.Println("publicInputs.json 生成成功！")

	fmt.Println("9. 测试编译电路···")
	var myCircuit offchain.CTRMiMCCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		panic("电路编译失败！")
	}
	fmt.Println("电路编译成功！")

	fmt.Println("10. 测试设置 pk, vk···")
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic("pk, vk 设置失败！")
	}
	fmt.Println("pk, vk 设置成功！")
	err = offchain.ExportVerifyingKey(vk, vkpath)
	if err != nil {
		panic("vk 导出失败！")
	}
	fmt.Println("vk 导出成功！")
	err = offchain.ExportProvingKey(pk, pkpath)
	if err != nil {
		panic("pk 导出失败！")
	}
	fmt.Println("pk 导出成功！")

	fmt.Println("11. 测试导出 proof···")
	var w offchain.CTRMiMCCircuit
	w.Key = key
	w.Nonce = nonce
	w.TextLen = textLen

	for i := 0; i < offchain.MAX_N; i++ {

		if i < textLen {
			w.Plaintext[i] = plaintext[i]
			w.Ciphertext[i] = ciphertext[i]
			w.Selector[i] = 1
		} else {
			w.Plaintext[i] = 0
			w.Ciphertext[i] = 0
			w.Selector[i] = 0
		}
	}
	offchain.ExportWitnessJSON(&w, witnesspath)

	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		panic("见证生成失败！")
	}
	fmt.Println("见证生成成功！")

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic("证明生成失败！")
	}
	fmt.Println("证明生成成功！")
	err = offchain.ExportProof(proof, proofpath)
	if err != nil {
		panic("proof 导出失败！")
	}
	fmt.Println("proof 导出成功！")

	fmt.Println("12. 测试买方验证···")
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	fmt.Println("买方验证成功！")
}
