/*
 * S3v2tov4 Proxy Server, (C) 2016 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"flag"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minio/s3v2tov4-proxy/s3auth"
	"github.com/vulcand/oxy/forward"
)

// Proxy from a V2 ingress to V4 egress.
type v2ToV4Proxy struct {
	fwdURL     *url.URL      // Minio forward endpoint.
	fwdHandler http.Handler  // Minio forwarding handler
	ingress    s3auth.Signer // signer at the ingress (V2)
	egress     s3auth.Signer // signer at the egress (v4)
}

func (p v2ToV4Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Authorization"), s3auth.SignV4Algorithm) {
		r.URL.Scheme = p.fwdURL.Scheme
		r.URL.Host = p.fwdURL.Host
		// If the signature is V4 then pass through the request as is
		// as it will be authenticated by the Minio server.
		p.fwdHandler.ServeHTTP(w, r)
		return
	}

	// url.RawPath will be valid if path has any encoded characters, if not it will
	// be empty - in which case we need to consider url.Path (bug in net/http?)
	encodedResource := r.URL.RawPath
	encodedQuery := r.URL.RawQuery
	if encodedResource == "" {
		splits := strings.Split(r.URL.Path, "?")
		if len(splits) > 0 {
			encodedResource = splits[0]
		}
	}

	expectedAuth := p.ingress.Sign(r.Method, encodedResource, encodedQuery, r.Header)
	gotAuth := r.Header.Get("Authorization")

	if gotAuth != expectedAuth {
		log.Printf("Signature mismatch error: got: %s, expected:%s\n", gotAuth, expectedAuth)
		errStr := "Signature mismatch"
		http.Error(w, errStr, http.StatusForbidden)
		return
	}

	dateStr := time.Now().UTC().Format(s3auth.DateFormat)
	r.Header.Set("X-Amz-Date", dateStr) // Mandatory for V4 signature.
	r.Header.Set("Host", r.Host)        // Host header at the ingress will be availabe as r.Host
	// We don't compute SHA256 for the data. (This is a proxy we won't be inspecting the data).
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	// In case _ or - ro ~ were encoded, decode it - to be V4 compatible.
	encodedResource = canonicalEncoding(encodedResource)
	encodedQuery = canonicalEncoding(encodedQuery)
	r.URL.RawPath = encodedResource
	r.URL.RawQuery = encodedQuery
	r.URL.Path = canonicalEncoding(r.URL.Path)

	// for encodedQuery, "/" should be encoded. (mc currently does not encode "/")
	encodedQuery = strings.Replace(encodedQuery, "/", "%2F", -1)
	r.Header.Set("Authorization", p.egress.Sign(r.Method, encodedResource, encodedQuery, r.Header))

	// Forward the request to Minio server.
	r.URL.Scheme = p.fwdURL.Scheme
	r.URL.Host = p.fwdURL.Host
	p.fwdHandler.ServeHTTP(w, r)
}

// Signature V4 spec mandates characters -, _, ~ not to be encoded.
func canonicalEncoding(str string) string {
	str = strings.Replace(str, "%2D", "-", -1)
	str = strings.Replace(str, "%5F", "_", -1)
	str = strings.Replace(str, "%7E", "~", -1)
	return str
}

// We have a no-op rewriter so that the forwarder does not add it's own headers.
type norewrite struct{}

func (r norewrite) Rewrite(req *http.Request) {}

func main() {
	// Local listening address for ingress data.
	listenAddr := flag.String("l", ":8000", "listen address (AWS S3 Signature V2)")
	// Forwarding address.
	fwdAddr := flag.String("f", "http://localhost:9000", "forward address (AWS S3 Signature V4)")

	// Credentials and region.
	accessKey := flag.String("access", "", "S3 access key")
	secretKey := flag.String("secret", "", "S3 secret key")
	region := flag.String("region", "us-east-1", "S3 bucket region")

	// If cert and key is specified we enable https on listening server.
	cert := flag.String("cert", "", "certficate for https")
	key := flag.String("key", "", "private-key for https")
	flag.Parse()

	u, err := url.Parse(*fwdAddr)
	if err != nil {
		log.Fatalln("Unrecognized forward address", *fwdAddr)
	}

	if *accessKey == "" || *secretKey == "" {
		log.Fatalln("access/secret key should be specified")
	}

	// Forwarding http.Handler
	fwd, err := forward.New(
		forward.PassHostHeader(true),
		forward.Rewriter(norewrite{}),
		forward.RoundTripper(&http.Transport{DisableCompression: true}),
	)
	if err != nil {
		log.Fatalln("Unable to initialize forwarding handler", err)
	}

	// HTTP server.
	server := &http.Server{
		Addr: *listenAddr,
		Handler: v2ToV4Proxy{
			fwdURL: u,
			ingress: s3auth.CredentialsV2{
				AccessKey: *accessKey,
				SecretKey: *secretKey,
				Region:    *region,
			},
			egress: s3auth.CredentialsV4{
				AccessKey: *accessKey,
				SecretKey: *secretKey,
				Region:    *region,
			},
			fwdHandler: fwd,
		},
	}

	if *cert != "" && *key != "" {
		err = server.ListenAndServeTLS(*cert, *key)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil {
		log.Fatalln("Unable to listen and serve", err)
	}
}
