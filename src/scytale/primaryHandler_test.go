/**
 * Copyright 2017 Comcast Cable Communications Management, LLC
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
 *
 */
package main

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestCopyRedirectHeaders(t *testing.T) {
	assert := assert.New(t)

	r, _ := http.NewRequest("GET", "http://example.com", nil)

	a, _ := http.NewRequest("GET", "http://example.com", nil)
	a.Header.Set("Authorization", "Invalid")

	via1 := make([]*http.Request, 1)
	via1[0] = a

	err := CopyRedirectHeaders(r, via1)

	assert.Nil(err)
	assert.Equal(r.Header["Authorization"][0], "Invalid")

	via11 := make([]*http.Request, 11)
	via11[0] = a

	r, _ = http.NewRequest("GET", "http://example.com", nil)
	err = CopyRedirectHeaders(r, via11)
	assert.NotNil(err)
}
