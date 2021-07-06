import { HttpClient } from '@angular/common/http'
import { Injectable } from '@angular/core'
import { Resolve } from '@angular/router'
import { Observable } from 'rxjs'

export interface User {
    active_config: number
    active_version: string
    custom_connection_gateway: string|null
    custom_connection_gateway_token: string|null
    is_pro: boolean
}

export interface Config {
    id: number
    content: string
    last_used_with_version: string
    created_at: Date
    modified_at: Date
}

export interface Version {
    version: string
}

export interface InstanceInfo {
    login_enabled: boolean
}

@Injectable({ providedIn: 'root' })
export class InstanceInfoResolver implements Resolve<Observable<InstanceInfo>> {
    constructor (private http: HttpClient) { }

    resolve(): Observable<InstanceInfo> {
        return this.http.get('/api/1/instance-info').toPromise()
    }
}