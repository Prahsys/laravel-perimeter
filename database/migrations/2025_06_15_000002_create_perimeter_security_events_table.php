<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        // Get the configured table prefix
        $prefix = Config::get('perimeter.storage.table_prefix', 'perimeter_');

        Schema::create($prefix.'security_events', function (Blueprint $table) use ($prefix) {
            $table->id();
            $table->foreignId('scan_id')->nullable()->constrained($prefix.'security_scans')->onDelete('cascade');
            $table->timestamp('timestamp')->index();
            $table->string('type')->index();
            $table->string('severity')->index();
            $table->string('description');
            $table->string('location')->nullable();
            $table->string('user')->nullable();
            $table->string('service')->nullable()->index();
            $table->json('details')->nullable();
            $table->timestamps();

            // Indexes for efficient querying
            $table->index('created_at');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        // Get the configured table prefix
        $prefix = Config::get('perimeter.storage.table_prefix', 'perimeter_');

        Schema::dropIfExists($prefix.'security_events');
    }
};
