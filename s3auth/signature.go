/*
 * AWS S3 Signature Auth, (C) 2016 Minio, Inc.
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

package s3auth

import "net/http"

// Signature related constants.
const (
	SignV2Algorithm = "AWS"
	SignV4Algorithm = "AWS4-HMAC-SHA256"
	DateFormat      = "20060102T150405Z"
	yyyymmdd        = "20060102"
)

// Signer interface for objects implementing Sign methods.
type Signer interface {
	Sign(method string, encodedResource string, encodedQuery string, headers http.Header) string
}
