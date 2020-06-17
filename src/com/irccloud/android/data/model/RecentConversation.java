/*
 * Copyright (c) 2015 IRCCloud, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.irccloud.android.data.model;

import androidx.room.Entity;
import androidx.room.Index;

import com.irccloud.android.data.collection.BuffersList;

@Entity(primaryKeys = {"cid", "bid"}, indices = {@Index(value = {"cid", "bid"}, unique = true)})
public class RecentConversation {
    private int cid;

    private int bid;

    private String name;

    private String type;

    private long timestamp;

    public int getCid() {
        return cid;
    }

    public void setCid(int cid) {
        this.cid = cid;
    }

    public int getBid() {
        return bid;
    }

    public void setBid(int bid) {
        this.bid = bid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public Buffer getBuffer() {
        Buffer b = BuffersList.getInstance().getBuffer(getBid());
        if(b == null) {
            b = new Buffer();
            b.setCid(getCid());
            b.setBid(getBid());
            b.setName(getName());
            b.setType(getType());
            b.setDeferred(1);
        }
        return b;
    }

    public String toString() {
        return "{cid: " + getCid() + ", bid: " + getBid() + ", name: " + getName() + ", type: " + getType() + "}";
    }
}