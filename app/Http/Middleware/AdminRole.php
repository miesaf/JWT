<?php

namespace App\Http\Middleware;

use Closure;

class AdminRole
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
        $payload = auth()->payload();

        if($payload->get('role') != 'admin') {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
