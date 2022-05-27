<?php

namespace App\Http\Controllers;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades;
use Illuminate\Support\Facades\Hash;




class AuthController extends Controller
{
    public function register(Request $request){
        $resFields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed',
        ]);
       
        $user = User::create([
            'name' => $resFields['name'],
            'email' => $resFields['email'],
            'password' => bcrypt($resFields['password'])
        ]);
        
        $token = $user->createToken('myapptoken')->plainTextToken;
        $response = [
            'user' => $user,
            'token' => $token
        ];

        return ($response);
        return true;// $response($response, 201);
    }
    public function login(Request $request){
        $resFields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
        ]);
        $user = User::where('email',$resFields['email'])->first();
        if(!$user || !Hash::check($resFields['password'],$user->password )){
            return response([
                'message' => 'bad credentials'                
            ], 401);
        }
        $token = $user->createToken('myapptoken')->plainTextToken;
        $response = [
            'user' => $user,
            'token' => $token
        ];
return $response;
    }
    public function logout(Request $request){
        auth()->user()->tokens()->delete();
        return [
            'message' => 'logout successfully'
        ];
    }
}
