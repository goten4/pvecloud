package main
import (
	"flag"
	"fmt"
	"os"
	"github.com/goten4/pvecloud/global"
	"github.com/goten4/pvecloud/auth"
)

func main() {

	help := flag.Bool("h", false, "show this help")
	version := flag.Bool("v", false, "show version")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] [COMMAND] [HOSTNAME]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "COMMANDS\n")
		fmt.Fprintf(os.Stderr, "  create\n")
		fmt.Fprintf(os.Stderr, "  start\n")
		fmt.Fprintf(os.Stderr, "  stop\n")
		fmt.Fprintf(os.Stderr, "  delete\n")
		fmt.Fprintf(os.Stderr, "  status\n")
		fmt.Fprintf(os.Stderr, "OPTIONS\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	if *version {
		fmt.Printf("PVECloud, version %s\n", global.Version)
		return
	}

	fmt.Println(auth.Cookie)
	fmt.Println(auth.CsrfToken)
}
