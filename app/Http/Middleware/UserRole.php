<?php

namespace App\Http\Middleware;

use Closure;

class UserRole
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if(auth()->user()->role == "user") {
            return $next($request);
        } else {
            if ($request->expectsJson()) {
                return response()->json(['status' => false, 'message' => 'Unauthorized'], 403);
            } else {
                return abort(403, "Unauthorized");
            }
        }
    }
}
