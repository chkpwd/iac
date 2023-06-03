package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
)

//go:embed templates/*
var folder embed.FS //embeds files to a virtual filesystem inside the go binary

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// w.Write([]byte(fmt.Sprintf("%v\n", r.RemoteAddr)))

		// fmt.Println(r.RequestURI)
		fmt.Println(r.URL.Path)

		if r.URL.Path == "/" {
			fldr, err := folder.ReadFile("templates/index.html")

			// Handle the error for the index.html file
			if err != nil {
				log.Fatal(err)
			}

			// Write the contents of the index.html file to the response
			w.Write(fldr)
			return
		}

		fldr, err := folder.ReadFile("templates/404.html")

		if err != nil {
			log.Fatal(err)
		}

		// Write the 404 status page
		w.Write(fldr)

	})

	http.HandleFunc("/css/styles.css", func(w http.ResponseWriter, r *http.Request) {

		fmt.Println(r.URL.Path)

		fldr, err := folder.ReadFile("templates/styles.css")

		// Handle the error for the index.html file
		if err != nil {
			log.Fatal(err)
		}

		// Write the contents of the index.html file to the response
		w.Header().Set("Content-Type", "text/css")
		w.Write(fldr)
	})

	err := http.ListenAndServe(":8081", nil)
	if err != nil {
		log.Fatal(err)
	}
}
