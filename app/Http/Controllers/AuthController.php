<?php

namespace App\Http\Controllers;

use Auth;
use Hash;
use Mail;
use Str;
use DB;
use Illuminate\Http\Request;
use App\Mail\APIResetPassword;
use App\Pengguna;
use Datetime;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'sendResetEmail']]);
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'username' => 'required|string|unique:pengguna',
            'email' => 'required|string|email|unique:pengguna',
            'role' => 'required|in:user,admin',
            'password' => 'required|string|min:8'
        ]);

        return Pengguna::create([
            'name' => $request['name'],
            'username' => $request['username'],
            'email' => $request['email'],
            'role' => $request['role'],
            'password' => Hash::make($request['password']),
        ]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['username', 'password']);

        $pengguna =  Pengguna::select('role')->find(request('username'));

        if (! $token = auth()->guard('api')->claims(['role' => $pengguna->role])->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->guard('api')->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }

    public function sendResetEmail(Request $request)
    {
        $validator = $request->validate([
            'email'  => 'required|email'
        ]);

        $acc = Pengguna::select('name')
                ->where('email', $request->email)
                ->first();

        if($acc != null) {
            $token = Str::random(60);
            $now = new DateTime();

            DB::table('password_resets')->updateOrInsert(
                ['email' => $request->email],
                ['token' => $token, 'created_at' => $now->format('Y-m-d H:i:s')]
            );

            $reset = (object) array();

            //Generate, the password reset link. The token generated is embedded in the link
            $reset->link = env('APP_FE_URL') . "/reset/$token";
            $reset->appName = env('APP_NAME');
            $reset->appURL = env('APP_FE_URL');

            Mail::to($request->email)->send(new APIResetPassword($reset));

            // check for failures
            if(Mail::failures()) {
                return response()->json(['status' => false, 'message' => 'Failed to send reset link email.']);
            } else {
                return response()->json(['status' => true, 'message' => 'Please check you email for reset link.']);
            }
        } else {
            return response()->json(['status' => false, 'message' => 'User not found or email not matched with login ID.']);
        }
    }
}
